rule TTP_XOR_MULT_DOSStub_cf3c {
  strings:
    $key_cf3c = { 9b 54 [2] ef 4c [2] a8 4e [2] ef 5f [2] a1 53 [2] ad 59 [2] ba 52 [2] a1 1c [2] 9c }

  condition:
    any of them
}