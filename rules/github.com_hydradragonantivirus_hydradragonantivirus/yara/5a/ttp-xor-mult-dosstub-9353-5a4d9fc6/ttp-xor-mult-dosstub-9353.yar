rule TTP_XOR_MULT_DOSStub_9353 {
  strings:
    $key_9353 = { c7 3b [2] b3 23 [2] f4 21 [2] b3 30 [2] fd 3c [2] f1 36 [2] e6 3d [2] fd 73 [2] c0 }

  condition:
    any of them
}