rule TTP_XOR_MULT_DOSStub_8252 {
  strings:
    $key_8252 = { d6 3a [2] a2 22 [2] e5 20 [2] a2 31 [2] ec 3d [2] e0 37 [2] f7 3c [2] ec 72 [2] d1 }

  condition:
    any of them
}