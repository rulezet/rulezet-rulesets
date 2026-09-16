rule TTP_XOR_MULT_DOSStub_9317 {
  strings:
    $key_9317 = { c7 7f [2] b3 67 [2] f4 65 [2] b3 74 [2] fd 78 [2] f1 72 [2] e6 79 [2] fd 37 [2] c0 }

  condition:
    any of them
}