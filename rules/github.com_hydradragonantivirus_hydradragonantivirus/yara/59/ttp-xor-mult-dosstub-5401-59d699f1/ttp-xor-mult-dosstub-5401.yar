rule TTP_XOR_MULT_DOSStub_5401 {
  strings:
    $key_5401 = { 00 69 [2] 74 71 [2] 33 73 [2] 74 62 [2] 3a 6e [2] 36 64 [2] 21 6f [2] 3a 21 [2] 07 }

  condition:
    any of them
}