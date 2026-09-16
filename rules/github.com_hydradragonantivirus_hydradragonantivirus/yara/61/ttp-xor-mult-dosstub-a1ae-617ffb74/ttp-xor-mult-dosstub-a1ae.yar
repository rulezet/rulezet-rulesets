rule TTP_XOR_MULT_DOSStub_a1ae {
  strings:
    $key_a1ae = { f5 c6 [2] 81 de [2] c6 dc [2] 81 cd [2] cf c1 [2] c3 cb [2] d4 c0 [2] cf 8e [2] f2 }

  condition:
    any of them
}