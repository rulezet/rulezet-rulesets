rule TTP_XOR_MULT_DOSStub_e547 {
  strings:
    $key_e547 = { b1 2f [2] c5 37 [2] 82 35 [2] c5 24 [2] 8b 28 [2] 87 22 [2] 90 29 [2] 8b 67 [2] b6 }

  condition:
    any of them
}