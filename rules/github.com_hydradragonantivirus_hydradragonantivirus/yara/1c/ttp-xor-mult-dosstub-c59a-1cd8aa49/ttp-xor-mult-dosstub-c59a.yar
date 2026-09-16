rule TTP_XOR_MULT_DOSStub_c59a {
  strings:
    $key_c59a = { 91 f2 [2] e5 ea [2] a2 e8 [2] e5 f9 [2] ab f5 [2] a7 ff [2] b0 f4 [2] ab ba [2] 96 }

  condition:
    any of them
}