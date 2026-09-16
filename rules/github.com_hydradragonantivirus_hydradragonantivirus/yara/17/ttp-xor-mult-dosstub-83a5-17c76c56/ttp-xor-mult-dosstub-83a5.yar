rule TTP_XOR_MULT_DOSStub_83a5 {
  strings:
    $key_83a5 = { d7 cd [2] a3 d5 [2] e4 d7 [2] a3 c6 [2] ed ca [2] e1 c0 [2] f6 cb [2] ed 85 [2] d0 }

  condition:
    any of them
}