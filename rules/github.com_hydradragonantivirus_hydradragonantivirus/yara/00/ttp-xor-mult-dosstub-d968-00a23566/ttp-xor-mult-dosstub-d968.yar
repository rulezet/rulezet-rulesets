rule TTP_XOR_MULT_DOSStub_d968 {
  strings:
    $key_d968 = { 8d 00 [2] f9 18 [2] be 1a [2] f9 0b [2] b7 07 [2] bb 0d [2] ac 06 [2] b7 48 [2] 8a }

  condition:
    any of them
}