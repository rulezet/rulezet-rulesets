rule TTP_XOR_MULT_DOSStub_6893 {
  strings:
    $key_6893 = { 3c fb [2] 48 e3 [2] 0f e1 [2] 48 f0 [2] 06 fc [2] 0a f6 [2] 1d fd [2] 06 b3 [2] 3b }

  condition:
    any of them
}