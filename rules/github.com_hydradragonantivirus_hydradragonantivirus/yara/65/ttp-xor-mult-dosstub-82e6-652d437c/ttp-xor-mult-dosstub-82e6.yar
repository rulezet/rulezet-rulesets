rule TTP_XOR_MULT_DOSStub_82e6 {
  strings:
    $key_82e6 = { d6 8e [2] a2 96 [2] e5 94 [2] a2 85 [2] ec 89 [2] e0 83 [2] f7 88 [2] ec c6 [2] d1 }

  condition:
    any of them
}