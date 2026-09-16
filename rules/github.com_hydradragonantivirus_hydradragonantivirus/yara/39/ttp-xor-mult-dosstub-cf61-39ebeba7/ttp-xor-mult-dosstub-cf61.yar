rule TTP_XOR_MULT_DOSStub_cf61 {
  strings:
    $key_cf61 = { 9b 09 [2] ef 11 [2] a8 13 [2] ef 02 [2] a1 0e [2] ad 04 [2] ba 0f [2] a1 41 [2] 9c }

  condition:
    any of them
}