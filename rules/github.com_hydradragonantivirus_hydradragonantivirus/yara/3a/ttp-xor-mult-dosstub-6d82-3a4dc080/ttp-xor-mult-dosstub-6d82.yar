rule TTP_XOR_MULT_DOSStub_6d82 {
  strings:
    $key_6d82 = { 39 ea [2] 4d f2 [2] 0a f0 [2] 4d e1 [2] 03 ed [2] 0f e7 [2] 18 ec [2] 03 a2 [2] 3e }

  condition:
    any of them
}