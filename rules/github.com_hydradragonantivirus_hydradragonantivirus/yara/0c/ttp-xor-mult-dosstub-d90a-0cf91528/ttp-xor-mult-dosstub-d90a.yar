rule TTP_XOR_MULT_DOSStub_d90a {
  strings:
    $key_d90a = { 8d 62 [2] f9 7a [2] be 78 [2] f9 69 [2] b7 65 [2] bb 6f [2] ac 64 [2] b7 2a [2] 8a }

  condition:
    any of them
}