rule TTP_XOR_MULT_DOSStub_8256 {
  strings:
    $key_8256 = { d6 3e [2] a2 26 [2] e5 24 [2] a2 35 [2] ec 39 [2] e0 33 [2] f7 38 [2] ec 76 [2] d1 }

  condition:
    any of them
}