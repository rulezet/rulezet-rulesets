rule TTP_XOR_MULT_DOSStub_f9b7 {
  strings:
    $key_f9b7 = { ad df [2] d9 c7 [2] 9e c5 [2] d9 d4 [2] 97 d8 [2] 9b d2 [2] 8c d9 [2] 97 97 [2] aa }

  condition:
    any of them
}