rule TTP_XOR_MULT_DOSStub_3a82 {
  strings:
    $key_3a82 = { 6e ea [2] 1a f2 [2] 5d f0 [2] 1a e1 [2] 54 ed [2] 58 e7 [2] 4f ec [2] 54 a2 [2] 69 }

  condition:
    any of them
}