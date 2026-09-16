rule TTP_XOR_MULT_DOSStub_ebdc {
  strings:
    $key_ebdc = { bf b4 [2] cb ac [2] 8c ae [2] cb bf [2] 85 b3 [2] 89 b9 [2] 9e b2 [2] 85 fc [2] b8 }

  condition:
    any of them
}