rule TTP_XOR_MULT_DOSStub_82f1 {
  strings:
    $key_82f1 = { d6 99 [2] a2 81 [2] e5 83 [2] a2 92 [2] ec 9e [2] e0 94 [2] f7 9f [2] ec d1 [2] d1 }

  condition:
    any of them
}