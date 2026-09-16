rule TTP_XOR_MULT_DOSStub_a51c {
  strings:
    $key_a51c = { f1 74 [2] 85 6c [2] c2 6e [2] 85 7f [2] cb 73 [2] c7 79 [2] d0 72 [2] cb 3c [2] f6 }

  condition:
    any of them
}