rule TTP_XOR_MULT_DOSStub_7893 {
  strings:
    $key_7893 = { 2c fb [2] 58 e3 [2] 1f e1 [2] 58 f0 [2] 16 fc [2] 1a f6 [2] 0d fd [2] 16 b3 [2] 2b }

  condition:
    any of them
}