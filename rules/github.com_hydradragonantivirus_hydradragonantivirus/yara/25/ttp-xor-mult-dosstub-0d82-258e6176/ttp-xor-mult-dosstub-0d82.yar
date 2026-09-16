rule TTP_XOR_MULT_DOSStub_0d82 {
  strings:
    $key_0d82 = { 59 ea [2] 2d f2 [2] 6a f0 [2] 2d e1 [2] 63 ed [2] 6f e7 [2] 78 ec [2] 63 a2 [2] 5e }

  condition:
    any of them
}