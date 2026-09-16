rule TTP_XOR_MULT_DOSStub_ee92 {
  strings:
    $key_ee92 = { ba fa [2] ce e2 [2] 89 e0 [2] ce f1 [2] 80 fd [2] 8c f7 [2] 9b fc [2] 80 b2 [2] bd }

  condition:
    any of them
}