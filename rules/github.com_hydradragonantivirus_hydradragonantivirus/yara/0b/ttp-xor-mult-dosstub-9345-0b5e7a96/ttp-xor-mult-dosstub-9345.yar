rule TTP_XOR_MULT_DOSStub_9345 {
  strings:
    $key_9345 = { c7 2d [2] b3 35 [2] f4 37 [2] b3 26 [2] fd 2a [2] f1 20 [2] e6 2b [2] fd 65 [2] c0 }

  condition:
    any of them
}