rule TTP_XOR_MULT_DOSStub_82fc {
  strings:
    $key_82fc = { d6 94 [2] a2 8c [2] e5 8e [2] a2 9f [2] ec 93 [2] e0 99 [2] f7 92 [2] ec dc [2] d1 }

  condition:
    any of them
}