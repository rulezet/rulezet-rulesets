rule TTP_XOR_MULT_DOSStub_9370 {
  strings:
    $key_9370 = { c7 18 [2] b3 00 [2] f4 02 [2] b3 13 [2] fd 1f [2] f1 15 [2] e6 1e [2] fd 50 [2] c0 }

  condition:
    any of them
}