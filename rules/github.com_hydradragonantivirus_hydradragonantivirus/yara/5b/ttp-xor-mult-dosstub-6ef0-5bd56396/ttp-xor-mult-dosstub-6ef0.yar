rule TTP_XOR_MULT_DOSStub_6ef0 {
  strings:
    $key_6ef0 = { 3a 98 [2] 4e 80 [2] 09 82 [2] 4e 93 [2] 00 9f [2] 0c 95 [2] 1b 9e [2] 00 d0 [2] 3d }

  condition:
    any of them
}