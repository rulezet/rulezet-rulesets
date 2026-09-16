rule TTP_XOR_MULT_DOSStub_1b85 {
  strings:
    $key_1b85 = { 4f ed [2] 3b f5 [2] 7c f7 [2] 3b e6 [2] 75 ea [2] 79 e0 [2] 6e eb [2] 75 a5 [2] 48 }

  condition:
    any of them
}