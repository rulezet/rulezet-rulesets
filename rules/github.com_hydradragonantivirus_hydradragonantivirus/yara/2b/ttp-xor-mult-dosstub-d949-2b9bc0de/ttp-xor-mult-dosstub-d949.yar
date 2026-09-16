rule TTP_XOR_MULT_DOSStub_d949 {
  strings:
    $key_d949 = { 8d 21 [2] f9 39 [2] be 3b [2] f9 2a [2] b7 26 [2] bb 2c [2] ac 27 [2] b7 69 [2] 8a }

  condition:
    any of them
}