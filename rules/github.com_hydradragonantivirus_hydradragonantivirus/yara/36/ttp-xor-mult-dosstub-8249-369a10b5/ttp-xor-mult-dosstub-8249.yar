rule TTP_XOR_MULT_DOSStub_8249 {
  strings:
    $key_8249 = { d6 21 [2] a2 39 [2] e5 3b [2] a2 2a [2] ec 26 [2] e0 2c [2] f7 27 [2] ec 69 [2] d1 }

  condition:
    any of them
}