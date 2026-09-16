rule TTP_XOR_MULT_DOSStub_a4eb {
  strings:
    $key_a4eb = { f0 83 [2] 84 9b [2] c3 99 [2] 84 88 [2] ca 84 [2] c6 8e [2] d1 85 [2] ca cb [2] f7 }

  condition:
    any of them
}