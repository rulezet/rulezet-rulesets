rule TTP_XOR_MULT_DOSStub_9360 {
  strings:
    $key_9360 = { c7 08 [2] b3 10 [2] f4 12 [2] b3 03 [2] fd 0f [2] f1 05 [2] e6 0e [2] fd 40 [2] c0 }

  condition:
    any of them
}