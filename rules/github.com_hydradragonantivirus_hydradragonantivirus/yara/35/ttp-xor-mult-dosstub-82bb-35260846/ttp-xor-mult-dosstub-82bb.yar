rule TTP_XOR_MULT_DOSStub_82bb {
  strings:
    $key_82bb = { d6 d3 [2] a2 cb [2] e5 c9 [2] a2 d8 [2] ec d4 [2] e0 de [2] f7 d5 [2] ec 9b [2] d1 }

  condition:
    any of them
}