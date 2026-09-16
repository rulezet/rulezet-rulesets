rule TTP_XOR_MULT_DOSStub_0bdc {
  strings:
    $key_0bdc = { 5f b4 [2] 2b ac [2] 6c ae [2] 2b bf [2] 65 b3 [2] 69 b9 [2] 7e b2 [2] 65 fc [2] 58 }

  condition:
    any of them
}