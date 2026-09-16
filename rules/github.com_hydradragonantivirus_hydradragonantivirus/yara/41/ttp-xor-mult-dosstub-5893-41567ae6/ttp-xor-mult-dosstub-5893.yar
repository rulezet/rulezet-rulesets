rule TTP_XOR_MULT_DOSStub_5893 {
  strings:
    $key_5893 = { 0c fb [2] 78 e3 [2] 3f e1 [2] 78 f0 [2] 36 fc [2] 3a f6 [2] 2d fd [2] 36 b3 [2] 0b }

  condition:
    any of them
}