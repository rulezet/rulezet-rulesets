rule TTP_XOR_MULT_DOSStub_6bdc {
  strings:
    $key_6bdc = { 3f b4 [2] 4b ac [2] 0c ae [2] 4b bf [2] 05 b3 [2] 09 b9 [2] 1e b2 [2] 05 fc [2] 38 }

  condition:
    any of them
}