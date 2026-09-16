rule TTP_XOR_MULT_DOSStub_8522 {
  strings:
    $key_8522 = { d1 4a [2] a5 52 [2] e2 50 [2] a5 41 [2] eb 4d [2] e7 47 [2] f0 4c [2] eb 02 [2] d6 }

  condition:
    any of them
}