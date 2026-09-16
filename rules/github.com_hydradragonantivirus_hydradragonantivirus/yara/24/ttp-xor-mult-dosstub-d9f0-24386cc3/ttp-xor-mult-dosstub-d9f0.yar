rule TTP_XOR_MULT_DOSStub_d9f0 {
  strings:
    $key_d9f0 = { 8d 98 [2] f9 80 [2] be 82 [2] f9 93 [2] b7 9f [2] bb 95 [2] ac 9e [2] b7 d0 [2] 8a }

  condition:
    any of them
}