rule TTP_XOR_MULT_DOSStub_d938 {
  strings:
    $key_d938 = { 8d 50 [2] f9 48 [2] be 4a [2] f9 5b [2] b7 57 [2] bb 5d [2] ac 56 [2] b7 18 [2] 8a }

  condition:
    any of them
}