rule TTP_XOR_MULT_DOSStub_76bf {
  strings:
    $key_76bf = { 22 d7 [2] 56 cf [2] 11 cd [2] 56 dc [2] 18 d0 [2] 14 da [2] 03 d1 [2] 18 9f [2] 25 }

  condition:
    any of them
}