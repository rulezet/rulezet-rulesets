rule TTP_XOR_MULT_DOSStub_14bf {
  strings:
    $key_14bf = { 40 d7 [2] 34 cf [2] 73 cd [2] 34 dc [2] 7a d0 [2] 76 da [2] 61 d1 [2] 7a 9f [2] 47 }

  condition:
    any of them
}