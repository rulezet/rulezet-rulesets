rule TTP_XOR_MULT_DOSStub_e747 {
  strings:
    $key_e747 = { b3 2f [2] c7 37 [2] 80 35 [2] c7 24 [2] 89 28 [2] 85 22 [2] 92 29 [2] 89 67 [2] b4 }

  condition:
    any of them
}