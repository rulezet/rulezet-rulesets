rule TTP_XOR_MULT_DOSStub_a8b2 {
  strings:
    $key_a8b2 = { fc da [2] 88 c2 [2] cf c0 [2] 88 d1 [2] c6 dd [2] ca d7 [2] dd dc [2] c6 92 [2] fb }

  condition:
    any of them
}