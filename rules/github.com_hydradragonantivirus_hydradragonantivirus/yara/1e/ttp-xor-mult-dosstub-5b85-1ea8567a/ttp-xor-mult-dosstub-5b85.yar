rule TTP_XOR_MULT_DOSStub_5b85 {
  strings:
    $key_5b85 = { 0f ed [2] 7b f5 [2] 3c f7 [2] 7b e6 [2] 35 ea [2] 39 e0 [2] 2e eb [2] 35 a5 [2] 08 }

  condition:
    any of them
}