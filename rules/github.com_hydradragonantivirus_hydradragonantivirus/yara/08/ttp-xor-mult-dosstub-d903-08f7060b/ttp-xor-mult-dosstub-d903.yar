rule TTP_XOR_MULT_DOSStub_d903 {
  strings:
    $key_d903 = { 8d 6b [2] f9 73 [2] be 71 [2] f9 60 [2] b7 6c [2] bb 66 [2] ac 6d [2] b7 23 [2] 8a }

  condition:
    any of them
}