rule TTP_XOR_MULT_DOSStub_9339 {
  strings:
    $key_9339 = { c7 51 [2] b3 49 [2] f4 4b [2] b3 5a [2] fd 56 [2] f1 5c [2] e6 57 [2] fd 19 [2] c0 }

  condition:
    any of them
}