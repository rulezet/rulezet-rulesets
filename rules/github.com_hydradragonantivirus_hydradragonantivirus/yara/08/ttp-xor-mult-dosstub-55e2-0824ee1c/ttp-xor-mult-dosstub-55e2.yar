rule TTP_XOR_MULT_DOSStub_55e2 {
  strings:
    $key_55e2 = { 01 8a [2] 75 92 [2] 32 90 [2] 75 81 [2] 3b 8d [2] 37 87 [2] 20 8c [2] 3b c2 [2] 06 }

  condition:
    any of them
}