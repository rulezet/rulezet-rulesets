rule TTP_XOR_MULT_DOSStub_7fdc {
  strings:
    $key_7fdc = { 2b b4 [2] 5f ac [2] 18 ae [2] 5f bf [2] 11 b3 [2] 1d b9 [2] 0a b2 [2] 11 fc [2] 2c }

  condition:
    any of them
}