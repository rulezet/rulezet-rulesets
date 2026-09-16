rule TTP_XOR_MULT_DOSStub_cf90 {
  strings:
    $key_cf90 = { 9b f8 [2] ef e0 [2] a8 e2 [2] ef f3 [2] a1 ff [2] ad f5 [2] ba fe [2] a1 b0 [2] 9c }

  condition:
    any of them
}