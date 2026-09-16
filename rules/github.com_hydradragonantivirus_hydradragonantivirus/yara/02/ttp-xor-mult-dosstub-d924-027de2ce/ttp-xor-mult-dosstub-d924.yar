rule TTP_XOR_MULT_DOSStub_d924 {
  strings:
    $key_d924 = { 8d 4c [2] f9 54 [2] be 56 [2] f9 47 [2] b7 4b [2] bb 41 [2] ac 4a [2] b7 04 [2] 8a }

  condition:
    any of them
}