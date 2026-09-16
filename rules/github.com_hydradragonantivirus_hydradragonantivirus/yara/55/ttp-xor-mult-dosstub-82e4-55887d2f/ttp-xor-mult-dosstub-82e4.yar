rule TTP_XOR_MULT_DOSStub_82e4 {
  strings:
    $key_82e4 = { d6 8c [2] a2 94 [2] e5 96 [2] a2 87 [2] ec 8b [2] e0 81 [2] f7 8a [2] ec c4 [2] d1 }

  condition:
    any of them
}