rule TTP_XOR_MULT_DOSStub_91ae {
  strings:
    $key_91ae = { c5 c6 [2] b1 de [2] f6 dc [2] b1 cd [2] ff c1 [2] f3 cb [2] e4 c0 [2] ff 8e [2] c2 }

  condition:
    any of them
}