rule TTP_XOR_MULT_DOSStub_d3b5 {
  strings:
    $key_d3b5 = { 87 dd [2] f3 c5 [2] b4 c7 [2] f3 d6 [2] bd da [2] b1 d0 [2] a6 db [2] bd 95 [2] 80 }

  condition:
    any of them
}