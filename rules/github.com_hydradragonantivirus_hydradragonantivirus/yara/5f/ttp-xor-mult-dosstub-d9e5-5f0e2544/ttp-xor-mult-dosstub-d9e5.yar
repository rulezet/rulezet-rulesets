rule TTP_XOR_MULT_DOSStub_d9e5 {
  strings:
    $key_d9e5 = { 8d 8d [2] f9 95 [2] be 97 [2] f9 86 [2] b7 8a [2] bb 80 [2] ac 8b [2] b7 c5 [2] 8a }

  condition:
    any of them
}