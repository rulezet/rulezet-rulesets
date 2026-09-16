rule TTP_XOR_MULT_DOSStub_fedc {
  strings:
    $key_fedc = { aa b4 [2] de ac [2] 99 ae [2] de bf [2] 90 b3 [2] 9c b9 [2] 8b b2 [2] 90 fc [2] ad }

  condition:
    any of them
}