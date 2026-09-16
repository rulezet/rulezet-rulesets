rule TTP_XOR_MULT_DOSStub_a5f2 {
  strings:
    $key_a5f2 = { f1 9a [2] 85 82 [2] c2 80 [2] 85 91 [2] cb 9d [2] c7 97 [2] d0 9c [2] cb d2 [2] f6 }

  condition:
    any of them
}