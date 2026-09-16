rule TTP_XOR_MULT_DOSStub_d290 {
  strings:
    $key_d290 = { 86 f8 [2] f2 e0 [2] b5 e2 [2] f2 f3 [2] bc ff [2] b0 f5 [2] a7 fe [2] bc b0 [2] 81 }

  condition:
    any of them
}