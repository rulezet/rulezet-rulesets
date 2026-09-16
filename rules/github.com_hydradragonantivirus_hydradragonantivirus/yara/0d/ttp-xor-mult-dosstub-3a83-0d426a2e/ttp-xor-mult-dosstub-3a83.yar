rule TTP_XOR_MULT_DOSStub_3a83 {
  strings:
    $key_3a83 = { 6e eb [2] 1a f3 [2] 5d f1 [2] 1a e0 [2] 54 ec [2] 58 e6 [2] 4f ed [2] 54 a3 [2] 69 }

  condition:
    any of them
}