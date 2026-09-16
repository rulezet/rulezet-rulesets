rule TTP_XOR_MULT_DOSStub_6b85 {
  strings:
    $key_6b85 = { 3f ed [2] 4b f5 [2] 0c f7 [2] 4b e6 [2] 05 ea [2] 09 e0 [2] 1e eb [2] 05 a5 [2] 38 }

  condition:
    any of them
}