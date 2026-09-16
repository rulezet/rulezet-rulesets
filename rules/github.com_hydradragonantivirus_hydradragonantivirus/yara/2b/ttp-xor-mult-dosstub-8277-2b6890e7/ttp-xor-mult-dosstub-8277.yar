rule TTP_XOR_MULT_DOSStub_8277 {
  strings:
    $key_8277 = { d6 1f [2] a2 07 [2] e5 05 [2] a2 14 [2] ec 18 [2] e0 12 [2] f7 19 [2] ec 57 [2] d1 }

  condition:
    any of them
}