rule TTP_XOR_MULT_DOSStub_c5bf {
  strings:
    $key_c5bf = { 91 d7 [2] e5 cf [2] a2 cd [2] e5 dc [2] ab d0 [2] a7 da [2] b0 d1 [2] ab 9f [2] 96 }

  condition:
    any of them
}