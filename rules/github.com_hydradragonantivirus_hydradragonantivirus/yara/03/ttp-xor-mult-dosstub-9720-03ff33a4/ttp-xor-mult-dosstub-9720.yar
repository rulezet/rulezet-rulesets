rule TTP_XOR_MULT_DOSStub_9720 {
  strings:
    $key_9720 = { c3 48 [2] b7 50 [2] f0 52 [2] b7 43 [2] f9 4f [2] f5 45 [2] e2 4e [2] f9 00 [2] c4 }

  condition:
    any of them
}