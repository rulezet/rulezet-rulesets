rule TTP_XOR_MULT_DOSStub_8212 {
  strings:
    $key_8212 = { d6 7a [2] a2 62 [2] e5 60 [2] a2 71 [2] ec 7d [2] e0 77 [2] f7 7c [2] ec 32 [2] d1 }

  condition:
    any of them
}