rule TTP_XOR_MULT_DOSStub_a5a5 {
  strings:
    $key_a5a5 = { f1 cd [2] 85 d5 [2] c2 d7 [2] 85 c6 [2] cb ca [2] c7 c0 [2] d0 cb [2] cb 85 [2] f6 }

  condition:
    any of them
}