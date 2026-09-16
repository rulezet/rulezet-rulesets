rule TTP_XOR_MULT_DOSStub_6ee7 {
  strings:
    $key_6ee7 = { 3a 8f [2] 4e 97 [2] 09 95 [2] 4e 84 [2] 00 88 [2] 0c 82 [2] 1b 89 [2] 00 c7 [2] 3d }

  condition:
    any of them
}