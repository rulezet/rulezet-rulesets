rule TTP_XOR_MULT_DOSStub_30e2 {
  strings:
    $key_30e2 = { 64 8a [2] 10 92 [2] 57 90 [2] 10 81 [2] 5e 8d [2] 52 87 [2] 45 8c [2] 5e c2 [2] 63 }

  condition:
    any of them
}