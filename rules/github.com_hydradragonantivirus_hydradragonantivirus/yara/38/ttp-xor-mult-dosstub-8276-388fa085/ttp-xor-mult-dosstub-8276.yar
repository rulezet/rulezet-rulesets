rule TTP_XOR_MULT_DOSStub_8276 {
  strings:
    $key_8276 = { d6 1e [2] a2 06 [2] e5 04 [2] a2 15 [2] ec 19 [2] e0 13 [2] f7 18 [2] ec 56 [2] d1 }

  condition:
    any of them
}