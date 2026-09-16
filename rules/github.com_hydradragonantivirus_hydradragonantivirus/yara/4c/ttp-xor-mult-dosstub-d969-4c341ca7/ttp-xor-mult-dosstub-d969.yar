rule TTP_XOR_MULT_DOSStub_d969 {
  strings:
    $key_d969 = { 8d 01 [2] f9 19 [2] be 1b [2] f9 0a [2] b7 06 [2] bb 0c [2] ac 07 [2] b7 49 [2] 8a }

  condition:
    any of them
}