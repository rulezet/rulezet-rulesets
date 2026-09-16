rule TTP_XOR_MULT_DOSStub_d9f9 {
  strings:
    $key_d9f9 = { 8d 91 [2] f9 89 [2] be 8b [2] f9 9a [2] b7 96 [2] bb 9c [2] ac 97 [2] b7 d9 [2] 8a }

  condition:
    any of them
}