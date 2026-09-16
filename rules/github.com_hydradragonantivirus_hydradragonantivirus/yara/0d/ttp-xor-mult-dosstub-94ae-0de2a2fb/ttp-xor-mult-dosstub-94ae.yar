rule TTP_XOR_MULT_DOSStub_94ae {
  strings:
    $key_94ae = { c0 c6 [2] b4 de [2] f3 dc [2] b4 cd [2] fa c1 [2] f6 cb [2] e1 c0 [2] fa 8e [2] c7 }

  condition:
    any of them
}