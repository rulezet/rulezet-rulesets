rule TTP_XOR_MULT_DOSStub_d9ee {
  strings:
    $key_d9ee = { 8d 86 [2] f9 9e [2] be 9c [2] f9 8d [2] b7 81 [2] bb 8b [2] ac 80 [2] b7 ce [2] 8a }

  condition:
    any of them
}