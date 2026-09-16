rule TTP_XOR_MULT_DOSStub_7a85 {
  strings:
    $key_7a85 = { 2e ed [2] 5a f5 [2] 1d f7 [2] 5a e6 [2] 14 ea [2] 18 e0 [2] 0f eb [2] 14 a5 [2] 29 }

  condition:
    any of them
}