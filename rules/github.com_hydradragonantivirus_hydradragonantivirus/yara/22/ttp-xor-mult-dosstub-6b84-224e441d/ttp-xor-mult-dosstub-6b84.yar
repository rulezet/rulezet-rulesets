rule TTP_XOR_MULT_DOSStub_6b84 {
  strings:
    $key_6b84 = { 3f ec [2] 4b f4 [2] 0c f6 [2] 4b e7 [2] 05 eb [2] 09 e1 [2] 1e ea [2] 05 a4 [2] 38 }

  condition:
    any of them
}