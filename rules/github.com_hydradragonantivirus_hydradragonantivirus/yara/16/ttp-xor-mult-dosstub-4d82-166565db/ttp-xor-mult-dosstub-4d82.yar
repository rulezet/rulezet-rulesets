rule TTP_XOR_MULT_DOSStub_4d82 {
  strings:
    $key_4d82 = { 19 ea [2] 6d f2 [2] 2a f0 [2] 6d e1 [2] 23 ed [2] 2f e7 [2] 38 ec [2] 23 a2 [2] 1e }

  condition:
    any of them
}