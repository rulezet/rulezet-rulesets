rule TTP_XOR_MULT_DOSStub_82e1 {
  strings:
    $key_82e1 = { d6 89 [2] a2 91 [2] e5 93 [2] a2 82 [2] ec 8e [2] e0 84 [2] f7 8f [2] ec c1 [2] d1 }

  condition:
    any of them
}