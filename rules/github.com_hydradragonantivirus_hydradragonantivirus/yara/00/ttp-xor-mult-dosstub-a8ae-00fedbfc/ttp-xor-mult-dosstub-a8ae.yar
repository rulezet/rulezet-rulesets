rule TTP_XOR_MULT_DOSStub_a8ae {
  strings:
    $key_a8ae = { fc c6 [2] 88 de [2] cf dc [2] 88 cd [2] c6 c1 [2] ca cb [2] dd c0 [2] c6 8e [2] fb }

  condition:
    any of them
}