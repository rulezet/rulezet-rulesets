rule TTP_XOR_MULT_DOSStub_0adc {
  strings:
    $key_0adc = { 5e b4 [2] 2a ac [2] 6d ae [2] 2a bf [2] 64 b3 [2] 68 b9 [2] 7f b2 [2] 64 fc [2] 59 }

  condition:
    any of them
}