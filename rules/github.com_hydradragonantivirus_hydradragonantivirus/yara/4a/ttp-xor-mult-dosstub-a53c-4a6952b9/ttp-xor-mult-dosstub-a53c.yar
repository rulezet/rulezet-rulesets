rule TTP_XOR_MULT_DOSStub_a53c {
  strings:
    $key_a53c = { f1 54 [2] 85 4c [2] c2 4e [2] 85 5f [2] cb 53 [2] c7 59 [2] d0 52 [2] cb 1c [2] f6 }

  condition:
    any of them
}