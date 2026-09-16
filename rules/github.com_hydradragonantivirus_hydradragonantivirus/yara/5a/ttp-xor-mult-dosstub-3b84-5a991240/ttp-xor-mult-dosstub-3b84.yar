rule TTP_XOR_MULT_DOSStub_3b84 {
  strings:
    $key_3b84 = { 6f ec [2] 1b f4 [2] 5c f6 [2] 1b e7 [2] 55 eb [2] 59 e1 [2] 4e ea [2] 55 a4 [2] 68 }

  condition:
    any of them
}