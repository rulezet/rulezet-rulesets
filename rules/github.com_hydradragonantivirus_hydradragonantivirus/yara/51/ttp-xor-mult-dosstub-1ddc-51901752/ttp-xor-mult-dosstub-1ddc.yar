rule TTP_XOR_MULT_DOSStub_1ddc {
  strings:
    $key_1ddc = { 49 b4 [2] 3d ac [2] 7a ae [2] 3d bf [2] 73 b3 [2] 7f b9 [2] 68 b2 [2] 73 fc [2] 4e }

  condition:
    any of them
}