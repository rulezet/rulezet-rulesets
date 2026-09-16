rule TTP_XOR_MULT_DOSStub_a50b {
  strings:
    $key_a50b = { f1 63 [2] 85 7b [2] c2 79 [2] 85 68 [2] cb 64 [2] c7 6e [2] d0 65 [2] cb 2b [2] f6 }

  condition:
    any of them
}