rule TTP_XOR_MULT_DOSStub_d929 {
  strings:
    $key_d929 = { 8d 41 [2] f9 59 [2] be 5b [2] f9 4a [2] b7 46 [2] bb 4c [2] ac 47 [2] b7 09 [2] 8a }

  condition:
    any of them
}