rule TTP_XOR_MULT_DOSStub_a5e1 {
  strings:
    $key_a5e1 = { f1 89 [2] 85 91 [2] c2 93 [2] 85 82 [2] cb 8e [2] c7 84 [2] d0 8f [2] cb c1 [2] f6 }

  condition:
    any of them
}