rule TTP_XOR_MULT_DOSStub_9376 {
  strings:
    $key_9376 = { c7 1e [2] b3 06 [2] f4 04 [2] b3 15 [2] fd 19 [2] f1 13 [2] e6 18 [2] fd 56 [2] c0 }

  condition:
    any of them
}