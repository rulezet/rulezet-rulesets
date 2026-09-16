rule TTP_XOR_MULT_DOSStub_9229 {
  strings:
    $key_9229 = { c6 41 [2] b2 59 [2] f5 5b [2] b2 4a [2] fc 46 [2] f0 4c [2] e7 47 [2] fc 09 [2] c1 }

  condition:
    any of them
}