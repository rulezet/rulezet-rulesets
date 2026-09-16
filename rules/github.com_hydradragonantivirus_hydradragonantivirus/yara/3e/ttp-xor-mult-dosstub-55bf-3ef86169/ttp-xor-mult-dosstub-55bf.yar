rule TTP_XOR_MULT_DOSStub_55bf {
  strings:
    $key_55bf = { 01 d7 [2] 75 cf [2] 32 cd [2] 75 dc [2] 3b d0 [2] 37 da [2] 20 d1 [2] 3b 9f [2] 06 }

  condition:
    any of them
}