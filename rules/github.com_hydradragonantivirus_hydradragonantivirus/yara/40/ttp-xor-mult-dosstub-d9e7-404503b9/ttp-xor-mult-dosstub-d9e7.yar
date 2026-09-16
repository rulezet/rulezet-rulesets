rule TTP_XOR_MULT_DOSStub_d9e7 {
  strings:
    $key_d9e7 = { 8d 8f [2] f9 97 [2] be 95 [2] f9 84 [2] b7 88 [2] bb 82 [2] ac 89 [2] b7 c7 [2] 8a }

  condition:
    any of them
}