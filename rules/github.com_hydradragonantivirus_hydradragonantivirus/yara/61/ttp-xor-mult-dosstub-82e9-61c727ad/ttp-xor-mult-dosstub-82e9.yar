rule TTP_XOR_MULT_DOSStub_82e9 {
  strings:
    $key_82e9 = { d6 81 [2] a2 99 [2] e5 9b [2] a2 8a [2] ec 86 [2] e0 8c [2] f7 87 [2] ec c9 [2] d1 }

  condition:
    any of them
}