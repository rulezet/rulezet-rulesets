rule TTP_XOR_MULT_DOSStub_5bdc {
  strings:
    $key_5bdc = { 0f b4 [2] 7b ac [2] 3c ae [2] 7b bf [2] 35 b3 [2] 39 b9 [2] 2e b2 [2] 35 fc [2] 08 }

  condition:
    any of them
}