rule TTP_XOR_MULT_DOSStub_c0bd {
  strings:
    $key_c0bd = { 94 d5 [2] e0 cd [2] a7 cf [2] e0 de [2] ae d2 [2] a2 d8 [2] b5 d3 [2] ae 9d [2] 93 }

  condition:
    any of them
}