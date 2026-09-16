rule TTP_XOR_MULT_DOSStub_f9d5 {
  strings:
    $key_f9d5 = { ad bd [2] d9 a5 [2] 9e a7 [2] d9 b6 [2] 97 ba [2] 9b b0 [2] 8c bb [2] 97 f5 [2] aa }

  condition:
    any of them
}