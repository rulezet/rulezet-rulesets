rule TTP_XOR_MULT_DOSStub_c18d {
  strings:
    $key_c18d = { 95 e5 [2] e1 fd [2] a6 ff [2] e1 ee [2] af e2 [2] a3 e8 [2] b4 e3 [2] af ad [2] 92 }

  condition:
    any of them
}