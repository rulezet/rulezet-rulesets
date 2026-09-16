rule TTP_XOR_MULT_DOSStub_d29a {
  strings:
    $key_d29a = { 86 f2 [2] f2 ea [2] b5 e8 [2] f2 f9 [2] bc f5 [2] b0 ff [2] a7 f4 [2] bc ba [2] 81 }

  condition:
    any of them
}