rule TTP_XOR_MULT_DOSStub_d978 {
  strings:
    $key_d978 = { 8d 10 [2] f9 08 [2] be 0a [2] f9 1b [2] b7 17 [2] bb 1d [2] ac 16 [2] b7 58 [2] 8a }

  condition:
    any of them
}