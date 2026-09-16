rule TTP_XOR_MULT_DOSStub_d28f {
  strings:
    $key_d28f = { 86 e7 [2] f2 ff [2] b5 fd [2] f2 ec [2] bc e0 [2] b0 ea [2] a7 e1 [2] bc af [2] 81 }

  condition:
    any of them
}