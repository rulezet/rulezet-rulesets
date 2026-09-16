rule TTP_XOR_MULT_DOSStub_8443 {
  strings:
    $key_8443 = { d0 2b [2] a4 33 [2] e3 31 [2] a4 20 [2] ea 2c [2] e6 26 [2] f1 2d [2] ea 63 [2] d7 }

  condition:
    any of them
}