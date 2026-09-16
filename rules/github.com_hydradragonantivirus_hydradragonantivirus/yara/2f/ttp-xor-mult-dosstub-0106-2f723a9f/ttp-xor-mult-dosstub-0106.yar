rule TTP_XOR_MULT_DOSStub_0106 {
  strings:
    $key_0106 = { 55 6e [2] 21 76 [2] 66 74 [2] 21 65 [2] 6f 69 [2] 63 63 [2] 74 68 [2] 6f 26 [2] 52 }

  condition:
    any of them
}