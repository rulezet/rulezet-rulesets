rule TTP_XOR_MULT_DOSStub_98ae {
  strings:
    $key_98ae = { cc c6 [2] b8 de [2] ff dc [2] b8 cd [2] f6 c1 [2] fa cb [2] ed c0 [2] f6 8e [2] cb }

  condition:
    any of them
}