rule TTP_XOR_MULT_DOSStub_84ae {
  strings:
    $key_84ae = { d0 c6 [2] a4 de [2] e3 dc [2] a4 cd [2] ea c1 [2] e6 cb [2] f1 c0 [2] ea 8e [2] d7 }

  condition:
    any of them
}