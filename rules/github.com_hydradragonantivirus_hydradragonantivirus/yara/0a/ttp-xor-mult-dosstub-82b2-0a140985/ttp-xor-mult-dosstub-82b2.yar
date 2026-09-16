rule TTP_XOR_MULT_DOSStub_82b2 {
  strings:
    $key_82b2 = { d6 da [2] a2 c2 [2] e5 c0 [2] a2 d1 [2] ec dd [2] e0 d7 [2] f7 dc [2] ec 92 [2] d1 }

  condition:
    any of them
}