rule TTP_XOR_MULT_DOSStub_46bf {
  strings:
    $key_46bf = { 12 d7 [2] 66 cf [2] 21 cd [2] 66 dc [2] 28 d0 [2] 24 da [2] 33 d1 [2] 28 9f [2] 15 }

  condition:
    any of them
}