rule TTP_XOR_MULT_DOSStub_a5ed {
  strings:
    $key_a5ed = { f1 85 [2] 85 9d [2] c2 9f [2] 85 8e [2] cb 82 [2] c7 88 [2] d0 83 [2] cb cd [2] f6 }

  condition:
    any of them
}