rule TTP_XOR_MULT_DOSStub_4adc {
  strings:
    $key_4adc = { 1e b4 [2] 6a ac [2] 2d ae [2] 6a bf [2] 24 b3 [2] 28 b9 [2] 3f b2 [2] 24 fc [2] 19 }

  condition:
    any of them
}