rule TTP_XOR_MULT_DOSStub_d9f8 {
  strings:
    $key_d9f8 = { 8d 90 [2] f9 88 [2] be 8a [2] f9 9b [2] b7 97 [2] bb 9d [2] ac 96 [2] b7 d8 [2] 8a }

  condition:
    any of them
}