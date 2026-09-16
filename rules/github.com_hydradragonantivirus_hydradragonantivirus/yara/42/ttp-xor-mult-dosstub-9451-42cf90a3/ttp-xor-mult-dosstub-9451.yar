rule TTP_XOR_MULT_DOSStub_9451 {
  strings:
    $key_9451 = { c0 39 [2] b4 21 [2] f3 23 [2] b4 32 [2] fa 3e [2] f6 34 [2] e1 3f [2] fa 71 [2] c7 }

  condition:
    any of them
}