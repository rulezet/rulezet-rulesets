rule TTP_XOR_MULT_DOSStub_e982 {
  strings:
    $key_e982 = { bd ea [2] c9 f2 [2] 8e f0 [2] c9 e1 [2] 87 ed [2] 8b e7 [2] 9c ec [2] 87 a2 [2] ba }

  condition:
    any of them
}