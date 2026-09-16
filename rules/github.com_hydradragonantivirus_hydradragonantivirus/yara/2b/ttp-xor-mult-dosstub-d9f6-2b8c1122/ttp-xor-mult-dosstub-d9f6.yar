rule TTP_XOR_MULT_DOSStub_d9f6 {
  strings:
    $key_d9f6 = { 8d 9e [2] f9 86 [2] be 84 [2] f9 95 [2] b7 99 [2] bb 93 [2] ac 98 [2] b7 d6 [2] 8a }

  condition:
    any of them
}