rule TTP_XOR_MULT_DOSStub_cf98 {
  strings:
    $key_cf98 = { 9b f0 [2] ef e8 [2] a8 ea [2] ef fb [2] a1 f7 [2] ad fd [2] ba f6 [2] a1 b8 [2] 9c }

  condition:
    any of them
}