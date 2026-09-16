rule TTP_XOR_MULT_DOSStub_d91a {
  strings:
    $key_d91a = { 8d 72 [2] f9 6a [2] be 68 [2] f9 79 [2] b7 75 [2] bb 7f [2] ac 74 [2] b7 3a [2] 8a }

  condition:
    any of them
}