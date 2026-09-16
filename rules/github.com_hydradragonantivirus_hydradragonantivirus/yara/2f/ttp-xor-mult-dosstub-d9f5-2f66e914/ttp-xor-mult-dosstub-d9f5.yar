rule TTP_XOR_MULT_DOSStub_d9f5 {
  strings:
    $key_d9f5 = { 8d 9d [2] f9 85 [2] be 87 [2] f9 96 [2] b7 9a [2] bb 90 [2] ac 9b [2] b7 d5 [2] 8a }

  condition:
    any of them
}