rule TTP_XOR_MULT_DOSStub_9310 {
  strings:
    $key_9310 = { c7 78 [2] b3 60 [2] f4 62 [2] b3 73 [2] fd 7f [2] f1 75 [2] e6 7e [2] fd 30 [2] c0 }

  condition:
    any of them
}