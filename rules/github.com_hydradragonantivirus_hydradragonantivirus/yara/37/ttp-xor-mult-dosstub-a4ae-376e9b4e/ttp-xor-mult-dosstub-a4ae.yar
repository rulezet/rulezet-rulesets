rule TTP_XOR_MULT_DOSStub_a4ae {
  strings:
    $key_a4ae = { f0 c6 [2] 84 de [2] c3 dc [2] 84 cd [2] ca c1 [2] c6 cb [2] d1 c0 [2] ca 8e [2] f7 }

  condition:
    any of them
}