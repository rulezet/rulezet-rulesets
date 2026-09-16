rule TTP_XOR_MULT_DOSStub_8274 {
  strings:
    $key_8274 = { d6 1c [2] a2 04 [2] e5 06 [2] a2 17 [2] ec 1b [2] e0 11 [2] f7 1a [2] ec 54 [2] d1 }

  condition:
    any of them
}