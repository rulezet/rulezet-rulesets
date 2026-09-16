rule TTP_XOR_MULT_DOSStub_87bf {
  strings:
    $key_87bf = { d3 d7 [2] a7 cf [2] e0 cd [2] a7 dc [2] e9 d0 [2] e5 da [2] f2 d1 [2] e9 9f [2] d4 }

  condition:
    any of them
}