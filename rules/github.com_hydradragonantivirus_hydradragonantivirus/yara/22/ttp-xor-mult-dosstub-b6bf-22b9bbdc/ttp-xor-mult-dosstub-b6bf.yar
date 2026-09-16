rule TTP_XOR_MULT_DOSStub_b6bf {
  strings:
    $key_b6bf = { e2 d7 [2] 96 cf [2] d1 cd [2] 96 dc [2] d8 d0 [2] d4 da [2] c3 d1 [2] d8 9f [2] e5 }

  condition:
    any of them
}