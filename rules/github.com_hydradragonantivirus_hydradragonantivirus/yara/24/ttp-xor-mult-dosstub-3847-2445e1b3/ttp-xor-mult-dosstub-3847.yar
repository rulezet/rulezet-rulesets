rule TTP_XOR_MULT_DOSStub_3847 {
  strings:
    $key_3847 = { 6c 2f [2] 18 37 [2] 5f 35 [2] 18 24 [2] 56 28 [2] 5a 22 [2] 4d 29 [2] 56 67 [2] 6b }

  condition:
    any of them
}