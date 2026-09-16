rule TTP_XOR_MULT_DOSStub_9338 {
  strings:
    $key_9338 = { c7 50 [2] b3 48 [2] f4 4a [2] b3 5b [2] fd 57 [2] f1 5d [2] e6 56 [2] fd 18 [2] c0 }

  condition:
    any of them
}