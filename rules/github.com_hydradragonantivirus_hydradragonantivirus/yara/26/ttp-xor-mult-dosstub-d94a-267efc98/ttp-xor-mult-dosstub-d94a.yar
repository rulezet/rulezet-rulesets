rule TTP_XOR_MULT_DOSStub_d94a {
  strings:
    $key_d94a = { 8d 22 [2] f9 3a [2] be 38 [2] f9 29 [2] b7 25 [2] bb 2f [2] ac 24 [2] b7 6a [2] 8a }

  condition:
    any of them
}