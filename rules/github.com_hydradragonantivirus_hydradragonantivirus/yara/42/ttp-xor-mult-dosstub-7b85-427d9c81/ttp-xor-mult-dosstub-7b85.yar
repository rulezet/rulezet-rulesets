rule TTP_XOR_MULT_DOSStub_7b85 {
  strings:
    $key_7b85 = { 2f ed [2] 5b f5 [2] 1c f7 [2] 5b e6 [2] 15 ea [2] 19 e0 [2] 0e eb [2] 15 a5 [2] 28 }

  condition:
    any of them
}