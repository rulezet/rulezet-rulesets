rule TTP_XOR_MULT_DOSStub_3106 {
  strings:
    $key_3106 = { 65 6e [2] 11 76 [2] 56 74 [2] 11 65 [2] 5f 69 [2] 53 63 [2] 44 68 [2] 5f 26 [2] 62 }

  condition:
    any of them
}