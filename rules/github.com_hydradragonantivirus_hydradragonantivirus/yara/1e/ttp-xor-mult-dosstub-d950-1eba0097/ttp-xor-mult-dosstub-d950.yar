rule TTP_XOR_MULT_DOSStub_d950 {
  strings:
    $key_d950 = { 8d 38 [2] f9 20 [2] be 22 [2] f9 33 [2] b7 3f [2] bb 35 [2] ac 3e [2] b7 70 [2] 8a }

  condition:
    any of them
}