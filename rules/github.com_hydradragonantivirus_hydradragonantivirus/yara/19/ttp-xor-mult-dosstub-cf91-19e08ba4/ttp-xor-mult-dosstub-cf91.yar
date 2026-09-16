rule TTP_XOR_MULT_DOSStub_cf91 {
  strings:
    $key_cf91 = { 9b f9 [2] ef e1 [2] a8 e3 [2] ef f2 [2] a1 fe [2] ad f4 [2] ba ff [2] a1 b1 [2] 9c }

  condition:
    any of them
}