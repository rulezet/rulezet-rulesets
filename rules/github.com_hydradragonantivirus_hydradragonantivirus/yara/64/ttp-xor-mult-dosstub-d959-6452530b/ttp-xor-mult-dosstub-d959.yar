rule TTP_XOR_MULT_DOSStub_d959 {
  strings:
    $key_d959 = { 8d 31 [2] f9 29 [2] be 2b [2] f9 3a [2] b7 36 [2] bb 3c [2] ac 37 [2] b7 79 [2] 8a }

  condition:
    any of them
}