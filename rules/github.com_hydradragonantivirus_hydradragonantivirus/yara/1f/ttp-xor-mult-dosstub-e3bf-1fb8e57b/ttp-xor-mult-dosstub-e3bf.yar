rule TTP_XOR_MULT_DOSStub_e3bf {
  strings:
    $key_e3bf = { b7 d7 [2] c3 cf [2] 84 cd [2] c3 dc [2] 8d d0 [2] 81 da [2] 96 d1 [2] 8d 9f [2] b0 }

  condition:
    any of them
}