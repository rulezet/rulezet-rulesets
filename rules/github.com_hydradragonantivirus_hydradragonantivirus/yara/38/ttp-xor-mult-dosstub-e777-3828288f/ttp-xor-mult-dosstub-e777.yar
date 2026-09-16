rule TTP_XOR_MULT_DOSStub_e777 {
  strings:
    $key_e777 = { b3 1f [2] c7 07 [2] 80 05 [2] c7 14 [2] 89 18 [2] 85 12 [2] 92 19 [2] 89 57 [2] b4 }

  condition:
    any of them
}