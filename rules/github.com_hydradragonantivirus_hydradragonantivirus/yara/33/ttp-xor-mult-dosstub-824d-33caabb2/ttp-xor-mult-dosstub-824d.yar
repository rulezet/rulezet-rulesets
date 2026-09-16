rule TTP_XOR_MULT_DOSStub_824d {
  strings:
    $key_824d = { d6 25 [2] a2 3d [2] e5 3f [2] a2 2e [2] ec 22 [2] e0 28 [2] f7 23 [2] ec 6d [2] d1 }

  condition:
    any of them
}