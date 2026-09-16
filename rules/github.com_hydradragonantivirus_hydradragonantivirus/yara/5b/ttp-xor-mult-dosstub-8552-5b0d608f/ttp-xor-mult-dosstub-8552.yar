rule TTP_XOR_MULT_DOSStub_8552 {
  strings:
    $key_8552 = { d1 3a [2] a5 22 [2] e2 20 [2] a5 31 [2] eb 3d [2] e7 37 [2] f0 3c [2] eb 72 [2] d6 }

  condition:
    any of them
}