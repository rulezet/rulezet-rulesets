rule TTP_XOR_MULT_DOSStub_ee98 {
  strings:
    $key_ee98 = { ba f0 [2] ce e8 [2] 89 ea [2] ce fb [2] 80 f7 [2] 8c fd [2] 9b f6 [2] 80 b8 [2] bd }

  condition:
    any of them
}