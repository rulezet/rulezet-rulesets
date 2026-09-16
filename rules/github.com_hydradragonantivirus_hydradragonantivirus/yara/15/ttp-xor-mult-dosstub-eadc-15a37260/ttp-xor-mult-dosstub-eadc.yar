rule TTP_XOR_MULT_DOSStub_eadc {
  strings:
    $key_eadc = { be b4 [2] ca ac [2] 8d ae [2] ca bf [2] 84 b3 [2] 88 b9 [2] 9f b2 [2] 84 fc [2] b9 }

  condition:
    any of them
}