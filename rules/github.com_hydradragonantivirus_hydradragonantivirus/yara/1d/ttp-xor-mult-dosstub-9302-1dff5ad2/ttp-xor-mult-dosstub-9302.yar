rule TTP_XOR_MULT_DOSStub_9302 {
  strings:
    $key_9302 = { c7 6a [2] b3 72 [2] f4 70 [2] b3 61 [2] fd 6d [2] f1 67 [2] e6 6c [2] fd 22 [2] c0 }

  condition:
    any of them
}