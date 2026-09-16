rule TTP_XOR_MULT_DOSStub_0ddc {
  strings:
    $key_0ddc = { 59 b4 [2] 2d ac [2] 6a ae [2] 2d bf [2] 63 b3 [2] 6f b9 [2] 78 b2 [2] 63 fc [2] 5e }

  condition:
    any of them
}