rule TTP_XOR_MULT_DOSStub_5a82 {
  strings:
    $key_5a82 = { 0e ea [2] 7a f2 [2] 3d f0 [2] 7a e1 [2] 34 ed [2] 38 e7 [2] 2f ec [2] 34 a2 [2] 09 }

  condition:
    any of them
}