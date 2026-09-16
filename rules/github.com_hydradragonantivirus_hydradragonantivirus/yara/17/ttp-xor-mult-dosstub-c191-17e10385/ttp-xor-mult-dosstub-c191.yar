rule TTP_XOR_MULT_DOSStub_c191 {
  strings:
    $key_c191 = { 95 f9 [2] e1 e1 [2] a6 e3 [2] e1 f2 [2] af fe [2] a3 f4 [2] b4 ff [2] af b1 [2] 92 }

  condition:
    any of them
}