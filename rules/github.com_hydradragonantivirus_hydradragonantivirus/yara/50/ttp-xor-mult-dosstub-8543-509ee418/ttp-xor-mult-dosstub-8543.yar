rule TTP_XOR_MULT_DOSStub_8543 {
  strings:
    $key_8543 = { d1 2b [2] a5 33 [2] e2 31 [2] a5 20 [2] eb 2c [2] e7 26 [2] f0 2d [2] eb 63 [2] d6 }

  condition:
    any of them
}