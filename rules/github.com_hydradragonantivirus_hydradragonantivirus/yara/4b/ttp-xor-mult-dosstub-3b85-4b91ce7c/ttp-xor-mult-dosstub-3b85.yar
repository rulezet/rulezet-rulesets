rule TTP_XOR_MULT_DOSStub_3b85 {
  strings:
    $key_3b85 = { 6f ed [2] 1b f5 [2] 5c f7 [2] 1b e6 [2] 55 ea [2] 59 e0 [2] 4e eb [2] 55 a5 [2] 68 }

  condition:
    any of them
}