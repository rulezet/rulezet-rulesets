rule TTP_XOR_MULT_DOSStub_1414 {
  strings:
    $key_1414 = { 40 7c [2] 34 64 [2] 73 66 [2] 34 77 [2] 7a 7b [2] 76 71 [2] 61 7a [2] 7a 34 [2] 47 }

  condition:
    any of them
}