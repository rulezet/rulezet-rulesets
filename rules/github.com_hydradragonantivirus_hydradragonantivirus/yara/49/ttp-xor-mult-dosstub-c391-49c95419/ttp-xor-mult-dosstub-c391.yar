rule TTP_XOR_MULT_DOSStub_c391 {
  strings:
    $key_c391 = { 97 f9 [2] e3 e1 [2] a4 e3 [2] e3 f2 [2] ad fe [2] a1 f4 [2] b6 ff [2] ad b1 [2] 90 }

  condition:
    any of them
}