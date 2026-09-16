rule TTP_XOR_MULT_DOSStub_d948 {
  strings:
    $key_d948 = { 8d 20 [2] f9 38 [2] be 3a [2] f9 2b [2] b7 27 [2] bb 2d [2] ac 26 [2] b7 68 [2] 8a }

  condition:
    any of them
}