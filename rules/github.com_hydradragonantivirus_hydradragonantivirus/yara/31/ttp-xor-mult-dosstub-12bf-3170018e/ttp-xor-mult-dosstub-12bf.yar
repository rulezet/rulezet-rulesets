rule TTP_XOR_MULT_DOSStub_12bf {
  strings:
    $key_12bf = { 46 d7 [2] 32 cf [2] 75 cd [2] 32 dc [2] 7c d0 [2] 70 da [2] 67 d1 [2] 7c 9f [2] 41 }

  condition:
    any of them
}