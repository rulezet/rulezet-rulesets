rule TTP_XOR_MULT_DOSStub_d96d {
  strings:
    $key_d96d = { 8d 05 [2] f9 1d [2] be 1f [2] f9 0e [2] b7 02 [2] bb 08 [2] ac 03 [2] b7 4d [2] 8a }

  condition:
    any of them
}