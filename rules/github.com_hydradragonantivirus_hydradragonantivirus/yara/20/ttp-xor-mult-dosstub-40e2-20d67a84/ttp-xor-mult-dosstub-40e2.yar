rule TTP_XOR_MULT_DOSStub_40e2 {
  strings:
    $key_40e2 = { 14 8a [2] 60 92 [2] 27 90 [2] 60 81 [2] 2e 8d [2] 22 87 [2] 35 8c [2] 2e c2 [2] 13 }

  condition:
    any of them
}