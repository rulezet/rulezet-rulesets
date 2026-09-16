rule TTP_XOR_MULT_DOSStub_71bf {
  strings:
    $key_71bf = { 25 d7 [2] 51 cf [2] 16 cd [2] 51 dc [2] 1f d0 [2] 13 da [2] 04 d1 [2] 1f 9f [2] 22 }

  condition:
    any of them
}