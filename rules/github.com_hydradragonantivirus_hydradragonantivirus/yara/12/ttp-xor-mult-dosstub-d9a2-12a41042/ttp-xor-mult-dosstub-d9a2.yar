rule TTP_XOR_MULT_DOSStub_d9a2 {
  strings:
    $key_d9a2 = { 8d ca [2] f9 d2 [2] be d0 [2] f9 c1 [2] b7 cd [2] bb c7 [2] ac cc [2] b7 82 [2] 8a }

  condition:
    any of them
}