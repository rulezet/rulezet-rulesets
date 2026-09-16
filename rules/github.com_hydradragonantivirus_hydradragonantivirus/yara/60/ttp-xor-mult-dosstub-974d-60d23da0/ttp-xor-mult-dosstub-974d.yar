rule TTP_XOR_MULT_DOSStub_974d {
  strings:
    $key_974d = { c3 25 [2] b7 3d [2] f0 3f [2] b7 2e [2] f9 22 [2] f5 28 [2] e2 23 [2] f9 6d [2] c4 }

  condition:
    any of them
}