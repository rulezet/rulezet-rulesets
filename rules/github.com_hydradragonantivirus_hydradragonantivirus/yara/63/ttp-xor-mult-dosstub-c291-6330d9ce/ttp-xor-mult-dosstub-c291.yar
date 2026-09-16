rule TTP_XOR_MULT_DOSStub_c291 {
  strings:
    $key_c291 = { 96 f9 [2] e2 e1 [2] a5 e3 [2] e2 f2 [2] ac fe [2] a0 f4 [2] b7 ff [2] ac b1 [2] 91 }

  condition:
    any of them
}