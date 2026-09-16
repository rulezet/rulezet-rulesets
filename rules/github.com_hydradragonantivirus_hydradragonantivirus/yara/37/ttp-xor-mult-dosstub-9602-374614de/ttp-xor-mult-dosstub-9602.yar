rule TTP_XOR_MULT_DOSStub_9602 {
  strings:
    $key_9602 = { c2 6a [2] b6 72 [2] f1 70 [2] b6 61 [2] f8 6d [2] f4 67 [2] e3 6c [2] f8 22 [2] c5 }

  condition:
    any of them
}