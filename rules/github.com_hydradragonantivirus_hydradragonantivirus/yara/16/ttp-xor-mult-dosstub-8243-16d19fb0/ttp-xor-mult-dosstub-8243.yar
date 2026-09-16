rule TTP_XOR_MULT_DOSStub_8243 {
  strings:
    $key_8243 = { d6 2b [2] a2 33 [2] e5 31 [2] a2 20 [2] ec 2c [2] e0 26 [2] f7 2d [2] ec 63 [2] d1 }

  condition:
    any of them
}