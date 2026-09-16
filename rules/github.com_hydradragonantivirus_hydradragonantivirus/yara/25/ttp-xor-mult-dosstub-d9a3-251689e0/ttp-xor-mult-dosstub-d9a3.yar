rule TTP_XOR_MULT_DOSStub_d9a3 {
  strings:
    $key_d9a3 = { 8d cb [2] f9 d3 [2] be d1 [2] f9 c0 [2] b7 cc [2] bb c6 [2] ac cd [2] b7 83 [2] 8a }

  condition:
    any of them
}