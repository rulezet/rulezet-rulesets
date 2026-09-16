rule TTP_XOR_MULT_DOSStub_d4f3 {
  strings:
    $key_d4f3 = { 80 9b [2] f4 83 [2] b3 81 [2] f4 90 [2] ba 9c [2] b6 96 [2] a1 9d [2] ba d3 [2] 87 }

  condition:
    any of them
}