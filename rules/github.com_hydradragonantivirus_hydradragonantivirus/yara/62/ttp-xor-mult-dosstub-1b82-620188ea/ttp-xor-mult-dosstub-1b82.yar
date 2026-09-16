rule TTP_XOR_MULT_DOSStub_1b82 {
  strings:
    $key_1b82 = { 4f ea [2] 3b f2 [2] 7c f0 [2] 3b e1 [2] 75 ed [2] 79 e7 [2] 6e ec [2] 75 a2 [2] 48 }

  condition:
    any of them
}