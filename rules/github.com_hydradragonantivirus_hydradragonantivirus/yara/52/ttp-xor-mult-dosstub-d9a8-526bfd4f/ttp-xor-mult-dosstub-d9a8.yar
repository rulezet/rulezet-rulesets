rule TTP_XOR_MULT_DOSStub_d9a8 {
  strings:
    $key_d9a8 = { 8d c0 [2] f9 d8 [2] be da [2] f9 cb [2] b7 c7 [2] bb cd [2] ac c6 [2] b7 88 [2] 8a }

  condition:
    any of them
}