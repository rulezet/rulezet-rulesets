rule TTP_XOR_MULT_DOSStub_1014 {
  strings:
    $key_1014 = { 44 7c [2] 30 64 [2] 77 66 [2] 30 77 [2] 7e 7b [2] 72 71 [2] 65 7a [2] 7e 34 [2] 43 }

  condition:
    any of them
}