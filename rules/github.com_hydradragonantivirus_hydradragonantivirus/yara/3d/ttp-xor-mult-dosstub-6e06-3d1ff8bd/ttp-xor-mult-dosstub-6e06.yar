rule TTP_XOR_MULT_DOSStub_6e06 {
  strings:
    $key_6e06 = { 3a 6e [2] 4e 76 [2] 09 74 [2] 4e 65 [2] 00 69 [2] 0c 63 [2] 1b 68 [2] 00 26 [2] 3d }

  condition:
    any of them
}