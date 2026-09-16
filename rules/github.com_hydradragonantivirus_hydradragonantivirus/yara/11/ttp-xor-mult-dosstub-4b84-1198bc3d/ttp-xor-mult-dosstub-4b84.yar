rule TTP_XOR_MULT_DOSStub_4b84 {
  strings:
    $key_4b84 = { 1f ec [2] 6b f4 [2] 2c f6 [2] 6b e7 [2] 25 eb [2] 29 e1 [2] 3e ea [2] 25 a4 [2] 18 }

  condition:
    any of them
}