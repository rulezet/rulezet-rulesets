rule TTP_XOR_MULT_DOSStub_c0bf {
  strings:
    $key_c0bf = { 94 d7 [2] e0 cf [2] a7 cd [2] e0 dc [2] ae d0 [2] a2 da [2] b5 d1 [2] ae 9f [2] 93 }

  condition:
    any of them
}