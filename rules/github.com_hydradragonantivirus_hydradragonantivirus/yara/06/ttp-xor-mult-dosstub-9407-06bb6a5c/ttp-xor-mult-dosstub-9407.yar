rule TTP_XOR_MULT_DOSStub_9407 {
  strings:
    $key_9407 = { c0 6f [2] b4 77 [2] f3 75 [2] b4 64 [2] fa 68 [2] f6 62 [2] e1 69 [2] fa 27 [2] c7 }

  condition:
    any of them
}