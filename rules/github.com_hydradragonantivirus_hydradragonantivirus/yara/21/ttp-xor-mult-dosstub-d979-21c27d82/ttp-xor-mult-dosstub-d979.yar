rule TTP_XOR_MULT_DOSStub_d979 {
  strings:
    $key_d979 = { 8d 11 [2] f9 09 [2] be 0b [2] f9 1a [2] b7 16 [2] bb 1c [2] ac 17 [2] b7 59 [2] 8a }

  condition:
    any of them
}