rule TTP_XOR_MULT_DOSStub_9312 {
  strings:
    $key_9312 = { c7 7a [2] b3 62 [2] f4 60 [2] b3 71 [2] fd 7d [2] f1 77 [2] e6 7c [2] fd 32 [2] c0 }

  condition:
    any of them
}