rule TTP_XOR_MULT_DOSStub_82ec {
  strings:
    $key_82ec = { d6 84 [2] a2 9c [2] e5 9e [2] a2 8f [2] ec 83 [2] e0 89 [2] f7 82 [2] ec cc [2] d1 }

  condition:
    any of them
}