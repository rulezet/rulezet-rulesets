rule TTP_XOR_MULT_DOSStub_e762 {
  strings:
    $key_e762 = { b3 0a [2] c7 12 [2] 80 10 [2] c7 01 [2] 89 0d [2] 85 07 [2] 92 0c [2] 89 42 [2] b4 }

  condition:
    any of them
}