rule TTP_XOR_MULT_DOSStub_f9d3 {
  strings:
    $key_f9d3 = { ad bb [2] d9 a3 [2] 9e a1 [2] d9 b0 [2] 97 bc [2] 9b b6 [2] 8c bd [2] 97 f3 [2] aa }

  condition:
    any of them
}