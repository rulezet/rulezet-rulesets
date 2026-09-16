rule TTP_XOR_MULT_DOSStub_d936 {
  strings:
    $key_d936 = { 8d 5e [2] f9 46 [2] be 44 [2] f9 55 [2] b7 59 [2] bb 53 [2] ac 58 [2] b7 16 [2] 8a }

  condition:
    any of them
}