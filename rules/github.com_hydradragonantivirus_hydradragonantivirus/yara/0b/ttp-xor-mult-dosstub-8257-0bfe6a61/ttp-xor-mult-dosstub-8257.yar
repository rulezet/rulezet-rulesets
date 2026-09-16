rule TTP_XOR_MULT_DOSStub_8257 {
  strings:
    $key_8257 = { d6 3f [2] a2 27 [2] e5 25 [2] a2 34 [2] ec 38 [2] e0 32 [2] f7 39 [2] ec 77 [2] d1 }

  condition:
    any of them
}