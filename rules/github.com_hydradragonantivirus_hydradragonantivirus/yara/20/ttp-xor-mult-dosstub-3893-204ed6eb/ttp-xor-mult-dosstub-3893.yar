rule TTP_XOR_MULT_DOSStub_3893 {
  strings:
    $key_3893 = { 6c fb [2] 18 e3 [2] 5f e1 [2] 18 f0 [2] 56 fc [2] 5a f6 [2] 4d fd [2] 56 b3 [2] 6b }

  condition:
    any of them
}