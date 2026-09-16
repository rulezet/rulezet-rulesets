rule TTP_XOR_MULT_DOSStub_a52b {
  strings:
    $key_a52b = { f1 43 [2] 85 5b [2] c2 59 [2] 85 48 [2] cb 44 [2] c7 4e [2] d0 45 [2] cb 0b [2] f6 }

  condition:
    any of them
}