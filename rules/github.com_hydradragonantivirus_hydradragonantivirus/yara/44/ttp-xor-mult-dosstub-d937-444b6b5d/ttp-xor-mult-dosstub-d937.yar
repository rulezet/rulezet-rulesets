rule TTP_XOR_MULT_DOSStub_d937 {
  strings:
    $key_d937 = { 8d 5f [2] f9 47 [2] be 45 [2] f9 54 [2] b7 58 [2] bb 52 [2] ac 59 [2] b7 17 [2] 8a }

  condition:
    any of them
}