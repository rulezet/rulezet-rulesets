rule TTP_XOR_MULT_DOSStub_d912 {
  strings:
    $key_d912 = { 8d 7a [2] f9 62 [2] be 60 [2] f9 71 [2] b7 7d [2] bb 77 [2] ac 7c [2] b7 32 [2] 8a }

  condition:
    any of them
}