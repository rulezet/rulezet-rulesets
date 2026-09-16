rule TTP_XOR_MULT_DOSStub_f2e4 {
  strings:
    $key_f2e4 = { a6 8c [2] d2 94 [2] 95 96 [2] d2 87 [2] 9c 8b [2] 90 81 [2] 87 8a [2] 9c c4 [2] a1 }

  condition:
    any of them
}