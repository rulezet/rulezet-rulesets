rule TTP_XOR_MULT_DOSStub_61bf {
  strings:
    $key_61bf = { 35 d7 [2] 41 cf [2] 06 cd [2] 41 dc [2] 0f d0 [2] 03 da [2] 14 d1 [2] 0f 9f [2] 32 }

  condition:
    any of them
}