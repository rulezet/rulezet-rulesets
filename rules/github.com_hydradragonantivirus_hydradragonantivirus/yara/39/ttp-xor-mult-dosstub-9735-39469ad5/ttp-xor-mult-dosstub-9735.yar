rule TTP_XOR_MULT_DOSStub_9735 {
  strings:
    $key_9735 = { c3 5d [2] b7 45 [2] f0 47 [2] b7 56 [2] f9 5a [2] f5 50 [2] e2 5b [2] f9 15 [2] c4 }

  condition:
    any of them
}