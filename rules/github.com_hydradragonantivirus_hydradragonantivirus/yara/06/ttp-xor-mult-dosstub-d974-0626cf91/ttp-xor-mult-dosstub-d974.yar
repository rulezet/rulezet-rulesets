rule TTP_XOR_MULT_DOSStub_d974 {
  strings:
    $key_d974 = { 8d 1c [2] f9 04 [2] be 06 [2] f9 17 [2] b7 1b [2] bb 11 [2] ac 1a [2] b7 54 [2] 8a }

  condition:
    any of them
}