rule TTP_XOR_MULT_DOSStub_9029 {
  strings:
    $key_9029 = { c4 41 [2] b0 59 [2] f7 5b [2] b0 4a [2] fe 46 [2] f2 4c [2] e5 47 [2] fe 09 [2] c3 }

  condition:
    any of them
}