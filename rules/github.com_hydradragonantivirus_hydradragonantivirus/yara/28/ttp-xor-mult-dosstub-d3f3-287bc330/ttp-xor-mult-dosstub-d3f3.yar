rule TTP_XOR_MULT_DOSStub_d3f3 {
  strings:
    $key_d3f3 = { 87 9b [2] f3 83 [2] b4 81 [2] f3 90 [2] bd 9c [2] b1 96 [2] a6 9d [2] bd d3 [2] 80 }

  condition:
    any of them
}