rule TTP_XOR_MULT_DOSStub_6fdc {
  strings:
    $key_6fdc = { 3b b4 [2] 4f ac [2] 08 ae [2] 4f bf [2] 01 b3 [2] 0d b9 [2] 1a b2 [2] 01 fc [2] 3c }

  condition:
    any of them
}