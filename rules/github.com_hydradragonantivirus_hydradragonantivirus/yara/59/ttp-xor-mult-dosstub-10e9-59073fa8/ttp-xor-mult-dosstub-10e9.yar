rule TTP_XOR_MULT_DOSStub_10e9 {
  strings:
    $key_10e9 = { 44 81 [2] 30 99 [2] 77 9b [2] 30 8a [2] 7e 86 [2] 72 8c [2] 65 87 [2] 7e c9 [2] 43 }

  condition:
    any of them
}