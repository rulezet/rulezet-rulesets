rule TTP_XOR_MULT_DOSStub_d8f3 {
  strings:
    $key_d8f3 = { 8c 9b [2] f8 83 [2] bf 81 [2] f8 90 [2] b6 9c [2] ba 96 [2] ad 9d [2] b6 d3 [2] 8b }

  condition:
    any of them
}