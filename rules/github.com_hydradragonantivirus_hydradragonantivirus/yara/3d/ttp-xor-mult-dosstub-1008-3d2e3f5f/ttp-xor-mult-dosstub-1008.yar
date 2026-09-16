rule TTP_XOR_MULT_DOSStub_1008 {
  strings:
    $key_1008 = { 44 60 [2] 30 78 [2] 77 7a [2] 30 6b [2] 7e 67 [2] 72 6d [2] 65 66 [2] 7e 28 [2] 43 }

  condition:
    any of them
}