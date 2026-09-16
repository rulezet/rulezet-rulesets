rule TTP_XOR_MULT_DOSStub_32bf {
  strings:
    $key_32bf = { 66 d7 [2] 12 cf [2] 55 cd [2] 12 dc [2] 5c d0 [2] 50 da [2] 47 d1 [2] 5c 9f [2] 61 }

  condition:
    any of them
}