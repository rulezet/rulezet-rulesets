rule TTP_XOR_MULT_DOSStub_4fdc {
  strings:
    $key_4fdc = { 1b b4 [2] 6f ac [2] 28 ae [2] 6f bf [2] 21 b3 [2] 2d b9 [2] 3a b2 [2] 21 fc [2] 1c }

  condition:
    any of them
}