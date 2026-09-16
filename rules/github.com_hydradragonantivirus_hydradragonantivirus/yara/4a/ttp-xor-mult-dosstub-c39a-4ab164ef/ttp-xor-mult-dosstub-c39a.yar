rule TTP_XOR_MULT_DOSStub_c39a {
  strings:
    $key_c39a = { 97 f2 [2] e3 ea [2] a4 e8 [2] e3 f9 [2] ad f5 [2] a1 ff [2] b6 f4 [2] ad ba [2] 90 }

  condition:
    any of them
}