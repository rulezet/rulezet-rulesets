rule TTP_XOR_MULT_DOSStub_824e {
  strings:
    $key_824e = { d6 26 [2] a2 3e [2] e5 3c [2] a2 2d [2] ec 21 [2] e0 2b [2] f7 20 [2] ec 6e [2] d1 }

  condition:
    any of them
}