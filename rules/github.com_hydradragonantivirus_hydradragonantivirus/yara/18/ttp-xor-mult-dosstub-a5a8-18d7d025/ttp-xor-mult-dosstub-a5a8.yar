rule TTP_XOR_MULT_DOSStub_a5a8 {
  strings:
    $key_a5a8 = { f1 c0 [2] 85 d8 [2] c2 da [2] 85 cb [2] cb c7 [2] c7 cd [2] d0 c6 [2] cb 88 [2] f6 }

  condition:
    any of them
}