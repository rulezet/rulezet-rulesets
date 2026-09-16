rule TTP_XOR_MULT_DOSStub_d963 {
  strings:
    $key_d963 = { 8d 0b [2] f9 13 [2] be 11 [2] f9 00 [2] b7 0c [2] bb 06 [2] ac 0d [2] b7 43 [2] 8a }

  condition:
    any of them
}