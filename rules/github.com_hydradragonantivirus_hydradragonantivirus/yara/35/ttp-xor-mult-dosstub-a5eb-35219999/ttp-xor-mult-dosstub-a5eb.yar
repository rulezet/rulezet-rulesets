rule TTP_XOR_MULT_DOSStub_a5eb {
  strings:
    $key_a5eb = { f1 83 [2] 85 9b [2] c2 99 [2] 85 88 [2] cb 84 [2] c7 8e [2] d0 85 [2] cb cb [2] f6 }

  condition:
    any of them
}