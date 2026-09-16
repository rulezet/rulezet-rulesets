rule TTP_XOR_MULT_DOSStub_82a8 {
  strings:
    $key_82a8 = { d6 c0 [2] a2 d8 [2] e5 da [2] a2 cb [2] ec c7 [2] e0 cd [2] f7 c6 [2] ec 88 [2] d1 }

  condition:
    any of them
}