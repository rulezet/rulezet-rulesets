rule TTP_XOR_MULT_DOSStub_1340 {
  strings:
    $key_1340 = { 47 28 [2] 33 30 [2] 74 32 [2] 33 23 [2] 7d 2f [2] 71 25 [2] 66 2e [2] 7d 60 [2] 40 }

  condition:
    any of them
}