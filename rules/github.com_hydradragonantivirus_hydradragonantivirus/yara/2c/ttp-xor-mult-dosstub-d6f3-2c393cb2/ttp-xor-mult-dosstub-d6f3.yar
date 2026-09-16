rule TTP_XOR_MULT_DOSStub_d6f3 {
  strings:
    $key_d6f3 = { 82 9b [2] f6 83 [2] b1 81 [2] f6 90 [2] b8 9c [2] b4 96 [2] a3 9d [2] b8 d3 [2] 85 }

  condition:
    any of them
}