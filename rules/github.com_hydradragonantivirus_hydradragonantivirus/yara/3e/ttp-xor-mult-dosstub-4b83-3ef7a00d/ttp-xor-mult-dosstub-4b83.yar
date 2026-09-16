rule TTP_XOR_MULT_DOSStub_4b83 {
  strings:
    $key_4b83 = { 1f eb [2] 6b f3 [2] 2c f1 [2] 6b e0 [2] 25 ec [2] 29 e6 [2] 3e ed [2] 25 a3 [2] 18 }

  condition:
    any of them
}