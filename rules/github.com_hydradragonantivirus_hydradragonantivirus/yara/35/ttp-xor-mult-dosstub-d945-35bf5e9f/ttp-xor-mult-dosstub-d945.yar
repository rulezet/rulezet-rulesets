rule TTP_XOR_MULT_DOSStub_d945 {
  strings:
    $key_d945 = { 8d 2d [2] f9 35 [2] be 37 [2] f9 26 [2] b7 2a [2] bb 20 [2] ac 2b [2] b7 65 [2] 8a }

  condition:
    any of them
}