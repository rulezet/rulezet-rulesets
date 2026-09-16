rule TTP_XOR_MULT_DOSStub_dcdc {
  strings:
    $key_dcdc = { 88 b4 [2] fc ac [2] bb ae [2] fc bf [2] b2 b3 [2] be b9 [2] a9 b2 [2] b2 fc [2] 8f }

  condition:
    any of them
}