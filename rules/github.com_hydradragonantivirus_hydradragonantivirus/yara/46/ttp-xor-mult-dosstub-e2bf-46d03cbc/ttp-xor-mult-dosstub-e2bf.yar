rule TTP_XOR_MULT_DOSStub_e2bf {
  strings:
    $key_e2bf = { b6 d7 [2] c2 cf [2] 85 cd [2] c2 dc [2] 8c d0 [2] 80 da [2] 97 d1 [2] 8c 9f [2] b1 }

  condition:
    any of them
}