rule TTP_XOR_MULT_DOSStub_1018 {
  strings:
    $key_1018 = { 44 70 [2] 30 68 [2] 77 6a [2] 30 7b [2] 7e 77 [2] 72 7d [2] 65 76 [2] 7e 38 [2] 43 }

  condition:
    any of them
}