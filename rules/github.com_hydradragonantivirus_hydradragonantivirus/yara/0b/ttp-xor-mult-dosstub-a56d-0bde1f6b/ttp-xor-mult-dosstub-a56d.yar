rule TTP_XOR_MULT_DOSStub_a56d {
  strings:
    $key_a56d = { f1 05 [2] 85 1d [2] c2 1f [2] 85 0e [2] cb 02 [2] c7 08 [2] d0 03 [2] cb 4d [2] f6 }

  condition:
    any of them
}