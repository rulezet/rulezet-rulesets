rule TTP_XOR_MULT_DOSStub_47bf {
  strings:
    $key_47bf = { 13 d7 [2] 67 cf [2] 20 cd [2] 67 dc [2] 29 d0 [2] 25 da [2] 32 d1 [2] 29 9f [2] 14 }

  condition:
    any of them
}