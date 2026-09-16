rule TTP_XOR_MULT_DOSStub_f9b0 {
  strings:
    $key_f9b0 = { ad d8 [2] d9 c0 [2] 9e c2 [2] d9 d3 [2] 97 df [2] 9b d5 [2] 8c de [2] 97 90 [2] aa }

  condition:
    any of them
}