rule TTP_XOR_MULT_DOSStub_3514 {
  strings:
    $key_3514 = { 61 7c [2] 15 64 [2] 52 66 [2] 15 77 [2] 5b 7b [2] 57 71 [2] 40 7a [2] 5b 34 [2] 66 }

  condition:
    any of them
}