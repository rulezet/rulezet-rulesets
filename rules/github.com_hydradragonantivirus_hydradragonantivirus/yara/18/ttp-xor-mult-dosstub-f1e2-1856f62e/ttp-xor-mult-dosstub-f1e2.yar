rule TTP_XOR_MULT_DOSStub_f1e2 {
  strings:
    $key_f1e2 = { a5 8a [2] d1 92 [2] 96 90 [2] d1 81 [2] 9f 8d [2] 93 87 [2] 84 8c [2] 9f c2 [2] a2 }

  condition:
    any of them
}