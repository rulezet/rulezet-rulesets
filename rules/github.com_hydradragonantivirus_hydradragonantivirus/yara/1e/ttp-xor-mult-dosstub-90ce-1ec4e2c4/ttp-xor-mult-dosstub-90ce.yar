rule TTP_XOR_MULT_DOSStub_90ce {
  strings:
    $key_90ce = { c4 a6 [2] b0 be [2] f7 bc [2] b0 ad [2] fe a1 [2] f2 ab [2] e5 a0 [2] fe ee [2] c3 }

  condition:
    any of them
}