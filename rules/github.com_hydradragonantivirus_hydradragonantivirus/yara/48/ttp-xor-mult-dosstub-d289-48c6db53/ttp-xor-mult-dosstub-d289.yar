rule TTP_XOR_MULT_DOSStub_d289 {
  strings:
    $key_d289 = { 86 e1 [2] f2 f9 [2] b5 fb [2] f2 ea [2] bc e6 [2] b0 ec [2] a7 e7 [2] bc a9 [2] 81 }

  condition:
    any of them
}