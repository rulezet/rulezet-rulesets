rule TTP_XOR_MULT_DOSStub_90ae {
  strings:
    $key_90ae = { c4 c6 [2] b0 de [2] f7 dc [2] b0 cd [2] fe c1 [2] f2 cb [2] e5 c0 [2] fe 8e [2] c3 }

  condition:
    any of them
}