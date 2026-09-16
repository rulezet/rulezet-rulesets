rule TTP_XOR_MULT_DOSStub_a5fb {
  strings:
    $key_a5fb = { f1 93 [2] 85 8b [2] c2 89 [2] 85 98 [2] cb 94 [2] c7 9e [2] d0 95 [2] cb db [2] f6 }

  condition:
    any of them
}