rule TTP_XOR_MULT_DOSStub_54e2 {
  strings:
    $key_54e2 = { 00 8a [2] 74 92 [2] 33 90 [2] 74 81 [2] 3a 8d [2] 36 87 [2] 21 8c [2] 3a c2 [2] 07 }

  condition:
    any of them
}