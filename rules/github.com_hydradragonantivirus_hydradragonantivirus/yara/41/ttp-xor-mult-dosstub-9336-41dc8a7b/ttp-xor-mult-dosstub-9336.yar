rule TTP_XOR_MULT_DOSStub_9336 {
  strings:
    $key_9336 = { c7 5e [2] b3 46 [2] f4 44 [2] b3 55 [2] fd 59 [2] f1 53 [2] e6 58 [2] fd 16 [2] c0 }

  condition:
    any of them
}