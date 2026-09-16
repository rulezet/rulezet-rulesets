rule TTP_XOR_MULT_DOSStub_d914 {
  strings:
    $key_d914 = { 8d 7c [2] f9 64 [2] be 66 [2] f9 77 [2] b7 7b [2] bb 71 [2] ac 7a [2] b7 34 [2] 8a }

  condition:
    any of them
}