rule TTP_XOR_MULT_DOSStub_cf94 {
  strings:
    $key_cf94 = { 9b fc [2] ef e4 [2] a8 e6 [2] ef f7 [2] a1 fb [2] ad f1 [2] ba fa [2] a1 b4 [2] 9c }

  condition:
    any of them
}