rule TTP_XOR_MULT_DOSStub_a51d {
  strings:
    $key_a51d = { f1 75 [2] 85 6d [2] c2 6f [2] 85 7e [2] cb 72 [2] c7 78 [2] d0 73 [2] cb 3d [2] f6 }

  condition:
    any of them
}