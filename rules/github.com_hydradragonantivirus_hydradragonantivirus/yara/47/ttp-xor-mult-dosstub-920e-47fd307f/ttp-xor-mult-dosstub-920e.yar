rule TTP_XOR_MULT_DOSStub_920e {
  strings:
    $key_920e = { c6 66 [2] b2 7e [2] f5 7c [2] b2 6d [2] fc 61 [2] f0 6b [2] e7 60 [2] fc 2e [2] c1 }

  condition:
    any of them
}