rule TTP_XOR_MULT_DOSStub_9341 {
  strings:
    $key_9341 = { c7 29 [2] b3 31 [2] f4 33 [2] b3 22 [2] fd 2e [2] f1 24 [2] e6 2f [2] fd 61 [2] c0 }

  condition:
    any of them
}