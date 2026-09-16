rule TTP_XOR_MULT_DOSStub_bcdc {
  strings:
    $key_bcdc = { e8 b4 [2] 9c ac [2] db ae [2] 9c bf [2] d2 b3 [2] de b9 [2] c9 b2 [2] d2 fc [2] ef }

  condition:
    any of them
}