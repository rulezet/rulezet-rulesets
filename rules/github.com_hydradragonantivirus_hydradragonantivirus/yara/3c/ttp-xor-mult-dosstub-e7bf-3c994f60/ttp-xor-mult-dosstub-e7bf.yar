rule TTP_XOR_MULT_DOSStub_e7bf {
  strings:
    $key_e7bf = { b3 d7 [2] c7 cf [2] 80 cd [2] c7 dc [2] 89 d0 [2] 85 da [2] 92 d1 [2] 89 9f [2] b4 }

  condition:
    any of them
}