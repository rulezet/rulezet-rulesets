rule TTP_XOR_MULT_DOSStub_5b84 {
  strings:
    $key_5b84 = { 0f ec [2] 7b f4 [2] 3c f6 [2] 7b e7 [2] 35 eb [2] 39 e1 [2] 2e ea [2] 35 a4 [2] 08 }

  condition:
    any of them
}