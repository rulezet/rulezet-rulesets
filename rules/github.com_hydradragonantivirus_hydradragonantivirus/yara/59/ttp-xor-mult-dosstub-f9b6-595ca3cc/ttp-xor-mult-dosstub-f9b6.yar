rule TTP_XOR_MULT_DOSStub_f9b6 {
  strings:
    $key_f9b6 = { ad de [2] d9 c6 [2] 9e c4 [2] d9 d5 [2] 97 d9 [2] 9b d3 [2] 8c d8 [2] 97 96 [2] aa }

  condition:
    any of them
}