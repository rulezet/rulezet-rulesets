rule TTP_XOR_MULT_DOSStub_d909 {
  strings:
    $key_d909 = { 8d 61 [2] f9 79 [2] be 7b [2] f9 6a [2] b7 66 [2] bb 6c [2] ac 67 [2] b7 29 [2] 8a }

  condition:
    any of them
}