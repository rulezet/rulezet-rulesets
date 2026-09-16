rule TTP_XOR_MULT_DOSStub_a5ba {
  strings:
    $key_a5ba = { f1 d2 [2] 85 ca [2] c2 c8 [2] 85 d9 [2] cb d5 [2] c7 df [2] d0 d4 [2] cb 9a [2] f6 }

  condition:
    any of them
}