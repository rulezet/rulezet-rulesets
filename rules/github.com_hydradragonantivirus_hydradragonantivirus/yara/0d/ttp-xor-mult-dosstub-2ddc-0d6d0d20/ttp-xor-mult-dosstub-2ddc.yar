rule TTP_XOR_MULT_DOSStub_2ddc {
  strings:
    $key_2ddc = { 79 b4 [2] 0d ac [2] 4a ae [2] 0d bf [2] 43 b3 [2] 4f b9 [2] 58 b2 [2] 43 fc [2] 7e }

  condition:
    any of them
}