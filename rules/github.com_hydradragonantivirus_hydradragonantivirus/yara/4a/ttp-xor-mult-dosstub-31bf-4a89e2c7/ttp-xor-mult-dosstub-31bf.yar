rule TTP_XOR_MULT_DOSStub_31bf {
  strings:
    $key_31bf = { 65 d7 [2] 11 cf [2] 56 cd [2] 11 dc [2] 5f d0 [2] 53 da [2] 44 d1 [2] 5f 9f [2] 62 }

  condition:
    any of them
}