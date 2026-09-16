rule TTP_XOR_MULT_DOSStub_6c06 {
  strings:
    $key_6c06 = { 38 6e [2] 4c 76 [2] 0b 74 [2] 4c 65 [2] 02 69 [2] 0e 63 [2] 19 68 [2] 02 26 [2] 3f }

  condition:
    any of them
}