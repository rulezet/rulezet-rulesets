rule TTP_XOR_MULT_DOSStub_9320 {
  strings:
    $key_9320 = { c7 48 [2] b3 50 [2] f4 52 [2] b3 43 [2] fd 4f [2] f1 45 [2] e6 4e [2] fd 00 [2] c0 }

  condition:
    any of them
}