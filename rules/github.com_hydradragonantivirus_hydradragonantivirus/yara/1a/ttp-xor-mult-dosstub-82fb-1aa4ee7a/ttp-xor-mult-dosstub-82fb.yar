rule TTP_XOR_MULT_DOSStub_82fb {
  strings:
    $key_82fb = { d6 93 [2] a2 8b [2] e5 89 [2] a2 98 [2] ec 94 [2] e0 9e [2] f7 95 [2] ec db [2] d1 }

  condition:
    any of them
}