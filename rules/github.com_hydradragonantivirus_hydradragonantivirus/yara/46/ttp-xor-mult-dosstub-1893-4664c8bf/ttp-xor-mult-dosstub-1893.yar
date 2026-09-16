rule TTP_XOR_MULT_DOSStub_1893 {
  strings:
    $key_1893 = { 4c fb [2] 38 e3 [2] 7f e1 [2] 38 f0 [2] 76 fc [2] 7a f6 [2] 6d fd [2] 76 b3 [2] 4b }

  condition:
    any of them
}