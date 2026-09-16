rule TTP_XOR_MULT_DOSStub_5b83 {
  strings:
    $key_5b83 = { 0f eb [2] 7b f3 [2] 3c f1 [2] 7b e0 [2] 35 ec [2] 39 e6 [2] 2e ed [2] 35 a3 [2] 08 }

  condition:
    any of them
}