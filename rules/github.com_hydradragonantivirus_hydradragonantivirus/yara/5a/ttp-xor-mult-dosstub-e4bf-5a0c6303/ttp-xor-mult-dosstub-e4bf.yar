rule TTP_XOR_MULT_DOSStub_e4bf {
  strings:
    $key_e4bf = { b0 d7 [2] c4 cf [2] 83 cd [2] c4 dc [2] 8a d0 [2] 86 da [2] 91 d1 [2] 8a 9f [2] b7 }

  condition:
    any of them
}