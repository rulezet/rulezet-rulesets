rule TTP_XOR_MULT_DOSStub_d940 {
  strings:
    $key_d940 = { 8d 28 [2] f9 30 [2] be 32 [2] f9 23 [2] b7 2f [2] bb 25 [2] ac 2e [2] b7 60 [2] 8a }

  condition:
    any of them
}