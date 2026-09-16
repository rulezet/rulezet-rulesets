rule TTP_XOR_MULT_DOSStub_cf95 {
  strings:
    $key_cf95 = { 9b fd [2] ef e5 [2] a8 e7 [2] ef f6 [2] a1 fa [2] ad f0 [2] ba fb [2] a1 b5 [2] 9c }

  condition:
    any of them
}