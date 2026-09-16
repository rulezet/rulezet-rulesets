rule TTP_XOR_MULT_DOSStub_a54f {
  strings:
    $key_a54f = { f1 27 [2] 85 3f [2] c2 3d [2] 85 2c [2] cb 20 [2] c7 2a [2] d0 21 [2] cb 6f [2] f6 }

  condition:
    any of them
}