rule TTP_XOR_MULT_DOSStub_6ddc {
  strings:
    $key_6ddc = { 39 b4 [2] 4d ac [2] 0a ae [2] 4d bf [2] 03 b3 [2] 0f b9 [2] 18 b2 [2] 03 fc [2] 3e }

  condition:
    any of them
}