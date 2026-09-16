rule TTP_XOR_MULT_DOSStub_cf6b {
  strings:
    $key_cf6b = { 9b 03 [2] ef 1b [2] a8 19 [2] ef 08 [2] a1 04 [2] ad 0e [2] ba 05 [2] a1 4b [2] 9c }

  condition:
    any of them
}