rule TTP_XOR_MULT_DOSStub_d28b {
  strings:
    $key_d28b = { 86 e3 [2] f2 fb [2] b5 f9 [2] f2 e8 [2] bc e4 [2] b0 ee [2] a7 e5 [2] bc ab [2] 81 }

  condition:
    any of them
}