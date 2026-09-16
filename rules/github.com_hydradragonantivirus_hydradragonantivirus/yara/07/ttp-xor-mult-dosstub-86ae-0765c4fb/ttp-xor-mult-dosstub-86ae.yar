rule TTP_XOR_MULT_DOSStub_86ae {
  strings:
    $key_86ae = { d2 c6 [2] a6 de [2] e1 dc [2] a6 cd [2] e8 c1 [2] e4 cb [2] f3 c0 [2] e8 8e [2] d5 }

  condition:
    any of them
}