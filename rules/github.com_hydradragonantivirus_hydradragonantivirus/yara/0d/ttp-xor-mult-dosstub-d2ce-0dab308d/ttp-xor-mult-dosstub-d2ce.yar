rule TTP_XOR_MULT_DOSStub_d2ce {
  strings:
    $key_d2ce = { 86 a6 [2] f2 be [2] b5 bc [2] f2 ad [2] bc a1 [2] b0 ab [2] a7 a0 [2] bc ee [2] 81 }

  condition:
    any of them
}