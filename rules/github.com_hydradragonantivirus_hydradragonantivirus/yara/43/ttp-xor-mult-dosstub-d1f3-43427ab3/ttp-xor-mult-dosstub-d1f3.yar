rule TTP_XOR_MULT_DOSStub_d1f3 {
  strings:
    $key_d1f3 = { 85 9b [2] f1 83 [2] b6 81 [2] f1 90 [2] bf 9c [2] b3 96 [2] a4 9d [2] bf d3 [2] 82 }

  condition:
    any of them
}