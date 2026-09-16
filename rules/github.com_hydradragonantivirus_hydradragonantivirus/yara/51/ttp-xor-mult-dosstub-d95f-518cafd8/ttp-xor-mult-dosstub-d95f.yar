rule TTP_XOR_MULT_DOSStub_d95f {
  strings:
    $key_d95f = { 8d 37 [2] f9 2f [2] be 2d [2] f9 3c [2] b7 30 [2] bb 3a [2] ac 31 [2] b7 7f [2] 8a }

  condition:
    any of them
}