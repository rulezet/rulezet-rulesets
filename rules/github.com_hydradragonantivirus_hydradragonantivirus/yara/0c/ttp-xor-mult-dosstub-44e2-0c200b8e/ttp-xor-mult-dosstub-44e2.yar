rule TTP_XOR_MULT_DOSStub_44e2 {
  strings:
    $key_44e2 = { 10 8a [2] 64 92 [2] 23 90 [2] 64 81 [2] 2a 8d [2] 26 87 [2] 31 8c [2] 2a c2 [2] 17 }

  condition:
    any of them
}