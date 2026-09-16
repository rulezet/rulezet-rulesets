rule TTP_XOR_MULT_DOSStub_2a82 {
  strings:
    $key_2a82 = { 7e ea [2] 0a f2 [2] 4d f0 [2] 0a e1 [2] 44 ed [2] 48 e7 [2] 5f ec [2] 44 a2 [2] 79 }

  condition:
    any of them
}