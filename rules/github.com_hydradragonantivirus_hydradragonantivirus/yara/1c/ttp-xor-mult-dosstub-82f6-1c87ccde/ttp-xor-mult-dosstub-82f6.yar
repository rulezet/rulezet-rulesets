rule TTP_XOR_MULT_DOSStub_82f6 {
  strings:
    $key_82f6 = { d6 9e [2] a2 86 [2] e5 84 [2] a2 95 [2] ec 99 [2] e0 93 [2] f7 98 [2] ec d6 [2] d1 }

  condition:
    any of them
}