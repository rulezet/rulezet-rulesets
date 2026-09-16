rule TTP_XOR_MULT_DOSStub_3d84 {
  strings:
    $key_3d84 = { 69 ec [2] 1d f4 [2] 5a f6 [2] 1d e7 [2] 53 eb [2] 5f e1 [2] 48 ea [2] 53 a4 [2] 6e }

  condition:
    any of them
}