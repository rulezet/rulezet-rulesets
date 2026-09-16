rule TTP_XOR_MULT_DOSStub_f9d1 {
  strings:
    $key_f9d1 = { ad b9 [2] d9 a1 [2] 9e a3 [2] d9 b2 [2] 97 be [2] 9b b4 [2] 8c bf [2] 97 f1 [2] aa }

  condition:
    any of them
}