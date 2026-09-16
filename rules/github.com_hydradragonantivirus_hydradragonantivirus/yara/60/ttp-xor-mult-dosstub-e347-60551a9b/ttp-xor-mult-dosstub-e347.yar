rule TTP_XOR_MULT_DOSStub_e347 {
  strings:
    $key_e347 = { b7 2f [2] c3 37 [2] 84 35 [2] c3 24 [2] 8d 28 [2] 81 22 [2] 96 29 [2] 8d 67 [2] b0 }

  condition:
    any of them
}