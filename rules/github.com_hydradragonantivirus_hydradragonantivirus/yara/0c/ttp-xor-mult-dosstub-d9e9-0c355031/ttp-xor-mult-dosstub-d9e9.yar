rule TTP_XOR_MULT_DOSStub_d9e9 {
  strings:
    $key_d9e9 = { 8d 81 [2] f9 99 [2] be 9b [2] f9 8a [2] b7 86 [2] bb 8c [2] ac 87 [2] b7 c9 [2] 8a }

  condition:
    any of them
}