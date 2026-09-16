rule TTP_XOR_MULT_DOSStub_6ef1 {
  strings:
    $key_6ef1 = { 3a 99 [2] 4e 81 [2] 09 83 [2] 4e 92 [2] 00 9e [2] 0c 94 [2] 1b 9f [2] 00 d1 [2] 3d }

  condition:
    any of them
}