rule TTP_XOR_MULT_DOSStub_d915 {
  strings:
    $key_d915 = { 8d 7d [2] f9 65 [2] be 67 [2] f9 76 [2] b7 7a [2] bb 70 [2] ac 7b [2] b7 35 [2] 8a }

  condition:
    any of them
}