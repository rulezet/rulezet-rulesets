rule TTP_XOR_MULT_DOSStub_9322 {
  strings:
    $key_9322 = { c7 4a [2] b3 52 [2] f4 50 [2] b3 41 [2] fd 4d [2] f1 47 [2] e6 4c [2] fd 02 [2] c0 }

  condition:
    any of them
}