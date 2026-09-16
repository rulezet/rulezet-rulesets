rule TTP_XOR_MULT_DOSStub_d916 {
  strings:
    $key_d916 = { 8d 7e [2] f9 66 [2] be 64 [2] f9 75 [2] b7 79 [2] bb 73 [2] ac 78 [2] b7 36 [2] 8a }

  condition:
    any of them
}