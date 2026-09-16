rule TTP_XOR_MULT_DOSStub_8245 {
  strings:
    $key_8245 = { d6 2d [2] a2 35 [2] e5 37 [2] a2 26 [2] ec 2a [2] e0 20 [2] f7 2b [2] ec 65 [2] d1 }

  condition:
    any of them
}