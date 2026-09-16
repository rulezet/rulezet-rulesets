rule TTP_XOR_MULT_DOSStub_9340 {
  strings:
    $key_9340 = { c7 28 [2] b3 30 [2] f4 32 [2] b3 23 [2] fd 2f [2] f1 25 [2] e6 2e [2] fd 60 [2] c0 }

  condition:
    any of them
}