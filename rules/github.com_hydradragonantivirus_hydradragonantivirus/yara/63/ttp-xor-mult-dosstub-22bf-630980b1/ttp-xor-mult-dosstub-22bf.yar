rule TTP_XOR_MULT_DOSStub_22bf {
  strings:
    $key_22bf = { 76 d7 [2] 02 cf [2] 45 cd [2] 02 dc [2] 4c d0 [2] 40 da [2] 57 d1 [2] 4c 9f [2] 71 }

  condition:
    any of them
}