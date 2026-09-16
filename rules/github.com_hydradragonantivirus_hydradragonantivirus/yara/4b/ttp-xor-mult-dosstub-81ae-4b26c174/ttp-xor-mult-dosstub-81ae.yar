rule TTP_XOR_MULT_DOSStub_81ae {
  strings:
    $key_81ae = { d5 c6 [2] a1 de [2] e6 dc [2] a1 cd [2] ef c1 [2] e3 cb [2] f4 c0 [2] ef 8e [2] d2 }

  condition:
    any of them
}