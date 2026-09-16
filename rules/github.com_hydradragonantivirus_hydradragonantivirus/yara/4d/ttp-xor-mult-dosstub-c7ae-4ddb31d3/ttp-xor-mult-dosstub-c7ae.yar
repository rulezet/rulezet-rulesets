rule TTP_XOR_MULT_DOSStub_c7ae {
  strings:
    $key_c7ae = { 93 c6 [2] e7 de [2] a0 dc [2] e7 cd [2] a9 c1 [2] a5 cb [2] b2 c0 [2] a9 8e [2] 94 }

  condition:
    any of them
}