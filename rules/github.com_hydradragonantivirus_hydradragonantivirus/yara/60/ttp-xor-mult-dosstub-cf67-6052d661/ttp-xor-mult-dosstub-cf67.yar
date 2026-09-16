rule TTP_XOR_MULT_DOSStub_cf67 {
  strings:
    $key_cf67 = { 9b 0f [2] ef 17 [2] a8 15 [2] ef 04 [2] a1 08 [2] ad 02 [2] ba 09 [2] a1 47 [2] 9c }

  condition:
    any of them
}