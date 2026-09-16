rule TTP_XOR_MULT_DOSStub_2d82 {
  strings:
    $key_2d82 = { 79 ea [2] 0d f2 [2] 4a f0 [2] 0d e1 [2] 43 ed [2] 4f e7 [2] 58 ec [2] 43 a2 [2] 7e }

  condition:
    any of them
}