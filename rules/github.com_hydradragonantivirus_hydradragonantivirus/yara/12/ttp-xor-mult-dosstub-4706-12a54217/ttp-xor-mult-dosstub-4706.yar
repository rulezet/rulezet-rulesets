rule TTP_XOR_MULT_DOSStub_4706 {
  strings:
    $key_4706 = { 13 6e [2] 67 76 [2] 20 74 [2] 67 65 [2] 29 69 [2] 25 63 [2] 32 68 [2] 29 26 [2] 14 }

  condition:
    any of them
}