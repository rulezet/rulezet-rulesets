rule TTP_XOR_MULT_DOSStub_01bf {
  strings:
    $key_01bf = { 55 d7 [2] 21 cf [2] 66 cd [2] 21 dc [2] 6f d0 [2] 63 da [2] 74 d1 [2] 6f 9f [2] 52 }

  condition:
    any of them
}