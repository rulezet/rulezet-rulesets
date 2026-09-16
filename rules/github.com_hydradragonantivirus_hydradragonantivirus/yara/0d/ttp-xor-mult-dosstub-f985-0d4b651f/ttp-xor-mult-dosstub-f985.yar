rule TTP_XOR_MULT_DOSStub_f985 {
  strings:
    $key_f985 = { ad ed [2] d9 f5 [2] 9e f7 [2] d9 e6 [2] 97 ea [2] 9b e0 [2] 8c eb [2] 97 a5 [2] aa }

  condition:
    any of them
}