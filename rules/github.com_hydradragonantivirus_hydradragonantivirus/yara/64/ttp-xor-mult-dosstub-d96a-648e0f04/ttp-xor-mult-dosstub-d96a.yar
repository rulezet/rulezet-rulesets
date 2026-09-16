rule TTP_XOR_MULT_DOSStub_d96a {
  strings:
    $key_d96a = { 8d 02 [2] f9 1a [2] be 18 [2] f9 09 [2] b7 05 [2] bb 0f [2] ac 04 [2] b7 4a [2] 8a }

  condition:
    any of them
}