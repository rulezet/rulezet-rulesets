rule TTP_XOR_MULT_DOSStub_9357 {
  strings:
    $key_9357 = { c7 3f [2] b3 27 [2] f4 25 [2] b3 34 [2] fd 38 [2] f1 32 [2] e6 39 [2] fd 77 [2] c0 }

  condition:
    any of them
}