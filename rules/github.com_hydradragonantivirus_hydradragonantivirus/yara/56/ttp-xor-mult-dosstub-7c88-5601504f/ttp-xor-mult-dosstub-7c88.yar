rule TTP_XOR_MULT_DOSStub_7c88 {
  strings:
    $key_7c88 = { 28 e0 [2] 5c f8 [2] 1b fa [2] 5c eb [2] 12 e7 [2] 1e ed [2] 09 e6 [2] 12 a8 [2] 2f }

  condition:
    any of them
}