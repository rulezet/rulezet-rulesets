rule TTP_XOR_MULT_DOSStub_8232 {
  strings:
    $key_8232 = { d6 5a [2] a2 42 [2] e5 40 [2] a2 51 [2] ec 5d [2] e0 57 [2] f7 5c [2] ec 12 [2] d1 }

  condition:
    any of them
}