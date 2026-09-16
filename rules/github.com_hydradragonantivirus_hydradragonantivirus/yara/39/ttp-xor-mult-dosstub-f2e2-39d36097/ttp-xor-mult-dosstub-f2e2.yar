rule TTP_XOR_MULT_DOSStub_f2e2 {
  strings:
    $key_f2e2 = { a6 8a [2] d2 92 [2] 95 90 [2] d2 81 [2] 9c 8d [2] 90 87 [2] 87 8c [2] 9c c2 [2] a1 }

  condition:
    any of them
}