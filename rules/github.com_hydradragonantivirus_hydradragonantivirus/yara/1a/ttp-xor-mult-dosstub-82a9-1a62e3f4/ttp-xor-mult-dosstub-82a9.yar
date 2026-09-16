rule TTP_XOR_MULT_DOSStub_82a9 {
  strings:
    $key_82a9 = { d6 c1 [2] a2 d9 [2] e5 db [2] a2 ca [2] ec c6 [2] e0 cc [2] f7 c7 [2] ec 89 [2] d1 }

  condition:
    any of them
}