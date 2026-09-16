rule TTP_XOR_MULT_DOSStub_d2bf {
  strings:
    $key_d2bf = { 86 d7 [2] f2 cf [2] b5 cd [2] f2 dc [2] bc d0 [2] b0 da [2] a7 d1 [2] bc 9f [2] 81 }

  condition:
    any of them
}