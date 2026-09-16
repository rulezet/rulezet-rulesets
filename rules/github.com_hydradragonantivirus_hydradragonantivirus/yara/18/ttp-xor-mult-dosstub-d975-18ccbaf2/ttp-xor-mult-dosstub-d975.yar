rule TTP_XOR_MULT_DOSStub_d975 {
  strings:
    $key_d975 = { 8d 1d [2] f9 05 [2] be 07 [2] f9 16 [2] b7 1a [2] bb 10 [2] ac 1b [2] b7 55 [2] 8a }

  condition:
    any of them
}