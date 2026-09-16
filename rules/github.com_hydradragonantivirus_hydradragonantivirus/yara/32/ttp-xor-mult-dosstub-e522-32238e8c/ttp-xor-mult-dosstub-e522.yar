rule TTP_XOR_MULT_DOSStub_e522 {
  strings:
    $key_e522 = { b1 4a [2] c5 52 [2] 82 50 [2] c5 41 [2] 8b 4d [2] 87 47 [2] 90 4c [2] 8b 02 [2] b6 }

  condition:
    any of them
}