rule TTP_XOR_MULT_DOSStub_d935 {
  strings:
    $key_d935 = { 8d 5d [2] f9 45 [2] be 47 [2] f9 56 [2] b7 5a [2] bb 50 [2] ac 5b [2] b7 15 [2] 8a }

  condition:
    any of them
}