rule TTP_XOR_MULT_DOSStub_8424 {
  strings:
    $key_8424 = { d0 4c [2] a4 54 [2] e3 56 [2] a4 47 [2] ea 4b [2] e6 41 [2] f1 4a [2] ea 04 [2] d7 }

  condition:
    any of them
}