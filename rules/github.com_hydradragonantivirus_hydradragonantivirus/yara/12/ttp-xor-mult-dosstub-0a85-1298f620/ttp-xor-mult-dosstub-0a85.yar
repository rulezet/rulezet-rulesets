rule TTP_XOR_MULT_DOSStub_0a85 {
  strings:
    $key_0a85 = { 5e ed [2] 2a f5 [2] 6d f7 [2] 2a e6 [2] 64 ea [2] 68 e0 [2] 7f eb [2] 64 a5 [2] 59 }

  condition:
    any of them
}