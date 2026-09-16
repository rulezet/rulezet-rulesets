rule TTP_XOR_MULT_DOSStub_2b85 {
  strings:
    $key_2b85 = { 7f ed [2] 0b f5 [2] 4c f7 [2] 0b e6 [2] 45 ea [2] 49 e0 [2] 5e eb [2] 45 a5 [2] 78 }

  condition:
    any of them
}