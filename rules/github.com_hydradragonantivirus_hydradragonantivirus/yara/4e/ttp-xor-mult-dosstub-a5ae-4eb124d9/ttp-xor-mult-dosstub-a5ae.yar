rule TTP_XOR_MULT_DOSStub_a5ae {
  strings:
    $key_a5ae = { f1 c6 [2] 85 de [2] c2 dc [2] 85 cd [2] cb c1 [2] c7 cb [2] d0 c0 [2] cb 8e [2] f6 }

  condition:
    any of them
}