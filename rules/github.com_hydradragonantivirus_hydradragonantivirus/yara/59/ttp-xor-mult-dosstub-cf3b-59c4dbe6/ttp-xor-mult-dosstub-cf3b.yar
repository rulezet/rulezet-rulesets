rule TTP_XOR_MULT_DOSStub_cf3b {
  strings:
    $key_cf3b = { 9b 53 [2] ef 4b [2] a8 49 [2] ef 58 [2] a1 54 [2] ad 5e [2] ba 55 [2] a1 1b [2] 9c }

  condition:
    any of them
}