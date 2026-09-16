rule TTP_XOR_MULT_DOSStub_d953 {
  strings:
    $key_d953 = { 8d 3b [2] f9 23 [2] be 21 [2] f9 30 [2] b7 3c [2] bb 36 [2] ac 3d [2] b7 73 [2] 8a }

  condition:
    any of them
}