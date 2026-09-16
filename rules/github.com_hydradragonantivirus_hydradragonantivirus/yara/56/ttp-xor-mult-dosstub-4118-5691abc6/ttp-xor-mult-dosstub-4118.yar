rule TTP_XOR_MULT_DOSStub_4118 {
  strings:
    $key_4118 = { 15 70 [2] 61 68 [2] 26 6a [2] 61 7b [2] 2f 77 [2] 23 7d [2] 34 76 [2] 2f 38 [2] 12 }

  condition:
    any of them
}