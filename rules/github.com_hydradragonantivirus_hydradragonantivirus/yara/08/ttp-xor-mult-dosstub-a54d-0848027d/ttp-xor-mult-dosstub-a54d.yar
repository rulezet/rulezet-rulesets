rule TTP_XOR_MULT_DOSStub_a54d {
  strings:
    $key_a54d = { f1 25 [2] 85 3d [2] c2 3f [2] 85 2e [2] cb 22 [2] c7 28 [2] d0 23 [2] cb 6d [2] f6 }

  condition:
    any of them
}