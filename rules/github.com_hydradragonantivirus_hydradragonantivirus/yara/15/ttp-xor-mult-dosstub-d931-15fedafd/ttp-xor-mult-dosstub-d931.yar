rule TTP_XOR_MULT_DOSStub_d931 {
  strings:
    $key_d931 = { 8d 59 [2] f9 41 [2] be 43 [2] f9 52 [2] b7 5e [2] bb 54 [2] ac 5f [2] b7 11 [2] 8a }

  condition:
    any of them
}