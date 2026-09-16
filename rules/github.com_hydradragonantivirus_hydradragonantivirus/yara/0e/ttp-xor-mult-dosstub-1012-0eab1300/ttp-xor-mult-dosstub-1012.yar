rule TTP_XOR_MULT_DOSStub_1012 {
  strings:
    $key_1012 = { 44 7a [2] 30 62 [2] 77 60 [2] 30 71 [2] 7e 7d [2] 72 77 [2] 65 7c [2] 7e 32 [2] 43 }

  condition:
    any of them
}