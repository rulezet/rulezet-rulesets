rule TTP_XOR_MULT_DOSStub_4a82 {
  strings:
    $key_4a82 = { 1e ea [2] 6a f2 [2] 2d f0 [2] 6a e1 [2] 24 ed [2] 28 e7 [2] 3f ec [2] 24 a2 [2] 19 }

  condition:
    any of them
}