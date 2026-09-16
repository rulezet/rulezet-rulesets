rule TTP_XOR_MULT_DOSStub_f9d4 {
  strings:
    $key_f9d4 = { ad bc [2] d9 a4 [2] 9e a6 [2] d9 b7 [2] 97 bb [2] 9b b1 [2] 8c ba [2] 97 f4 [2] aa }

  condition:
    any of them
}