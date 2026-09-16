rule TTP_XOR_MULT_DOSStub_50e2 {
  strings:
    $key_50e2 = { 04 8a [2] 70 92 [2] 37 90 [2] 70 81 [2] 3e 8d [2] 32 87 [2] 25 8c [2] 3e c2 [2] 03 }

  condition:
    any of them
}