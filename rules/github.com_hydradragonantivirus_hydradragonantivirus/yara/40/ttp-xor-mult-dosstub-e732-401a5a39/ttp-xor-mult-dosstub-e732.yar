rule TTP_XOR_MULT_DOSStub_e732 {
  strings:
    $key_e732 = { b3 5a [2] c7 42 [2] 80 40 [2] c7 51 [2] 89 5d [2] 85 57 [2] 92 5c [2] 89 12 [2] b4 }

  condition:
    any of them
}