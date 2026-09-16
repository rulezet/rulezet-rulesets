rule TTP_XOR_MULT_DOSStub_0b85 {
  strings:
    $key_0b85 = { 5f ed [2] 2b f5 [2] 6c f7 [2] 2b e6 [2] 65 ea [2] 69 e0 [2] 7e eb [2] 65 a5 [2] 58 }

  condition:
    any of them
}