rule TTP_XOR_MULT_DOSStub_91ce {
  strings:
    $key_91ce = { c5 a6 [2] b1 be [2] f6 bc [2] b1 ad [2] ff a1 [2] f3 ab [2] e4 a0 [2] ff ee [2] c2 }

  condition:
    any of them
}