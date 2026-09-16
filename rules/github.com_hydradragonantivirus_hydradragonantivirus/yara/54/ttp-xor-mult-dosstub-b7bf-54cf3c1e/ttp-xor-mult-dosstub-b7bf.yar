rule TTP_XOR_MULT_DOSStub_b7bf {
  strings:
    $key_b7bf = { e3 d7 [2] 97 cf [2] d0 cd [2] 97 dc [2] d9 d0 [2] d5 da [2] c2 d1 [2] d9 9f [2] e4 }

  condition:
    any of them
}