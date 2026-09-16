rule TTP_XOR_MULT_DOSStub_d9f3 {
  strings:
    $key_d9f3 = { 8d 9b [2] f9 83 [2] be 81 [2] f9 90 [2] b7 9c [2] bb 96 [2] ac 9d [2] b7 d3 [2] 8a }

  condition:
    any of them
}