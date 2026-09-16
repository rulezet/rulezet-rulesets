rule TTP_XOR_MULT_DOSStub_17bf {
  strings:
    $key_17bf = { 43 d7 [2] 37 cf [2] 70 cd [2] 37 dc [2] 79 d0 [2] 75 da [2] 62 d1 [2] 79 9f [2] 44 }

  condition:
    any of them
}