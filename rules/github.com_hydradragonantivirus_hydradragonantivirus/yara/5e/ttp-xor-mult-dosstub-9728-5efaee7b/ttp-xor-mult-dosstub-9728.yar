rule TTP_XOR_MULT_DOSStub_9728 {
  strings:
    $key_9728 = { c3 40 [2] b7 58 [2] f0 5a [2] b7 4b [2] f9 47 [2] f5 4d [2] e2 46 [2] f9 08 [2] c4 }

  condition:
    any of them
}