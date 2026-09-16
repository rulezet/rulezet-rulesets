rule TTP_XOR_MULT_DOSStub_f982 {
  strings:
    $key_f982 = { ad ea [2] d9 f2 [2] 9e f0 [2] d9 e1 [2] 97 ed [2] 9b e7 [2] 8c ec [2] 97 a2 [2] aa }

  condition:
    any of them
}