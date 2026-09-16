rule TTP_XOR_MULT_DOSStub_d962 {
  strings:
    $key_d962 = { 8d 0a [2] f9 12 [2] be 10 [2] f9 01 [2] b7 0d [2] bb 07 [2] ac 0c [2] b7 42 [2] 8a }

  condition:
    any of them
}