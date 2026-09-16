rule TTP_XOR_MULT_DOSStub_2fdc {
  strings:
    $key_2fdc = { 7b b4 [2] 0f ac [2] 48 ae [2] 0f bf [2] 41 b3 [2] 4d b9 [2] 5a b2 [2] 41 fc [2] 7c }

  condition:
    any of them
}