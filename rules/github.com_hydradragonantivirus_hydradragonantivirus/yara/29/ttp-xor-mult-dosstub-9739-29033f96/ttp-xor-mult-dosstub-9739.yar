rule TTP_XOR_MULT_DOSStub_9739 {
  strings:
    $key_9739 = { c3 51 [2] b7 49 [2] f0 4b [2] b7 5a [2] f9 56 [2] f5 5c [2] e2 57 [2] f9 19 [2] c4 }

  condition:
    any of them
}