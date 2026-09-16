rule TTP_XOR_MULT_DOSStub_9331 {
  strings:
    $key_9331 = { c7 59 [2] b3 41 [2] f4 43 [2] b3 52 [2] fd 5e [2] f1 54 [2] e6 5f [2] fd 11 [2] c0 }

  condition:
    any of them
}