rule TTP_XOR_MULT_DOSStub_63e2 {
  strings:
    $key_63e2 = { 37 8a [2] 43 92 [2] 04 90 [2] 43 81 [2] 0d 8d [2] 01 87 [2] 16 8c [2] 0d c2 [2] 30 }

  condition:
    any of them
}