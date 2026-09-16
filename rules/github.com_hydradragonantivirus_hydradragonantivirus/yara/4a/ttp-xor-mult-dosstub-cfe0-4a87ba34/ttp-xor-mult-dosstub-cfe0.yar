rule TTP_XOR_MULT_DOSStub_cfe0 {
  strings:
    $key_cfe0 = { 9b 88 [2] ef 90 [2] a8 92 [2] ef 83 [2] a1 8f [2] ad 85 [2] ba 8e [2] a1 c0 [2] 9c }

  condition:
    any of them
}