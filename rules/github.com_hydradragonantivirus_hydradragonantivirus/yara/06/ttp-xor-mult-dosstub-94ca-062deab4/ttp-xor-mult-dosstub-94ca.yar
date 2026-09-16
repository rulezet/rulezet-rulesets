rule TTP_XOR_MULT_DOSStub_94ca {
  strings:
    $key_94ca = { c0 a2 [2] b4 ba [2] f3 b8 [2] b4 a9 [2] fa a5 [2] f6 af [2] e1 a4 [2] fa ea [2] c7 }

  condition:
    any of them
}