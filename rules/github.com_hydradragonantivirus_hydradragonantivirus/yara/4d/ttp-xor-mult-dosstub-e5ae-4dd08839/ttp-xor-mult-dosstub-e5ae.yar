rule TTP_XOR_MULT_DOSStub_e5ae {
  strings:
    $key_e5ae = { b1 c6 [2] c5 de [2] 82 dc [2] c5 cd [2] 8b c1 [2] 87 cb [2] 90 c0 [2] 8b 8e [2] b6 }

  condition:
    any of them
}