rule TTP_XOR_MULT_DOSStub_f9d8 {
  strings:
    $key_f9d8 = { ad b0 [2] d9 a8 [2] 9e aa [2] d9 bb [2] 97 b7 [2] 9b bd [2] 8c b6 [2] 97 f8 [2] aa }

  condition:
    any of them
}