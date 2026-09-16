rule TTP_XOR_MULT_DOSStub_2cdc {
  strings:
    $key_2cdc = { 78 b4 [2] 0c ac [2] 4b ae [2] 0c bf [2] 42 b3 [2] 4e b9 [2] 59 b2 [2] 42 fc [2] 7f }

  condition:
    any of them
}