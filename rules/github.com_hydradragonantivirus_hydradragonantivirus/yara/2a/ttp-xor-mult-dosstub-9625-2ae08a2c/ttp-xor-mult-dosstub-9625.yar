rule TTP_XOR_MULT_DOSStub_9625 {
  strings:
    $key_9625 = { c2 4d [2] b6 55 [2] f1 57 [2] b6 46 [2] f8 4a [2] f4 40 [2] e3 4b [2] f8 05 [2] c5 }

  condition:
    any of them
}