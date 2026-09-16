rule TTP_XOR_MULT_DOSStub_82aa {
  strings:
    $key_82aa = { d6 c2 [2] a2 da [2] e5 d8 [2] a2 c9 [2] ec c5 [2] e0 cf [2] f7 c4 [2] ec 8a [2] d1 }

  condition:
    any of them
}