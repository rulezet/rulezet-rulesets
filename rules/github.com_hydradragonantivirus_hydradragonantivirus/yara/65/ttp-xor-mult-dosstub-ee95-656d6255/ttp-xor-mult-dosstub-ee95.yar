rule TTP_XOR_MULT_DOSStub_ee95 {
  strings:
    $key_ee95 = { ba fd [2] ce e5 [2] 89 e7 [2] ce f6 [2] 80 fa [2] 8c f0 [2] 9b fb [2] 80 b5 [2] bd }

  condition:
    any of them
}