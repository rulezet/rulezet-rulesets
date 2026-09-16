rule TTP_XOR_MULT_DOSStub_d934 {
  strings:
    $key_d934 = { 8d 5c [2] f9 44 [2] be 46 [2] f9 57 [2] b7 5b [2] bb 51 [2] ac 5a [2] b7 14 [2] 8a }

  condition:
    any of them
}