rule TTP_XOR_MULT_DOSStub_d2bd {
  strings:
    $key_d2bd = { 86 d5 [2] f2 cd [2] b5 cf [2] f2 de [2] bc d2 [2] b0 d8 [2] a7 d3 [2] bc 9d [2] 81 }

  condition:
    any of them
}