rule TTP_XOR_MULT_DOSStub_8553 {
  strings:
    $key_8553 = { d1 3b [2] a5 23 [2] e2 21 [2] a5 30 [2] eb 3c [2] e7 36 [2] f0 3d [2] eb 73 [2] d6 }

  condition:
    any of them
}