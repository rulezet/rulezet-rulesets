rule TTP_XOR_MULT_DOSStub_f4bf {
  strings:
    $key_f4bf = { a0 d7 [2] d4 cf [2] 93 cd [2] d4 dc [2] 9a d0 [2] 96 da [2] 81 d1 [2] 9a 9f [2] a7 }

  condition:
    any of them
}