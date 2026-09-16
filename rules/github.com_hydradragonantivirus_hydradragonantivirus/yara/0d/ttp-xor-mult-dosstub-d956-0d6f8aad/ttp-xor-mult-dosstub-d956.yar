rule TTP_XOR_MULT_DOSStub_d956 {
  strings:
    $key_d956 = { 8d 3e [2] f9 26 [2] be 24 [2] f9 35 [2] b7 39 [2] bb 33 [2] ac 38 [2] b7 76 [2] 8a }

  condition:
    any of them
}