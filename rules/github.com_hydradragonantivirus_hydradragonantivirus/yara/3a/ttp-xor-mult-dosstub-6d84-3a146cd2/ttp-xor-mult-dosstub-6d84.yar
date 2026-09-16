rule TTP_XOR_MULT_DOSStub_6d84 {
  strings:
    $key_6d84 = { 39 ec [2] 4d f4 [2] 0a f6 [2] 4d e7 [2] 03 eb [2] 0f e1 [2] 18 ea [2] 03 a4 [2] 3e }

  condition:
    any of them
}