rule TTP_XOR_MULT_DOSStub_cf04 {
  strings:
    $key_cf04 = { 9b 6c [2] ef 74 [2] a8 76 [2] ef 67 [2] a1 6b [2] ad 61 [2] ba 6a [2] a1 24 [2] 9c }

  condition:
    any of them
}