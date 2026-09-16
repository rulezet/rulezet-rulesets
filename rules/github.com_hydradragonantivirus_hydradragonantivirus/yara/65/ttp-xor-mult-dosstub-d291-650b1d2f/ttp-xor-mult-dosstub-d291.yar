rule TTP_XOR_MULT_DOSStub_d291 {
  strings:
    $key_d291 = { 86 f9 [2] f2 e1 [2] b5 e3 [2] f2 f2 [2] bc fe [2] b0 f4 [2] a7 ff [2] bc b1 [2] 81 }

  condition:
    any of them
}