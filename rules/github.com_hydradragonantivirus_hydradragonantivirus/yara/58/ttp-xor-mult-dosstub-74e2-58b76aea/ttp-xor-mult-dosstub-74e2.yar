rule TTP_XOR_MULT_DOSStub_74e2 {
  strings:
    $key_74e2 = { 20 8a [2] 54 92 [2] 13 90 [2] 54 81 [2] 1a 8d [2] 16 87 [2] 01 8c [2] 1a c2 [2] 27 }

  condition:
    any of them
}