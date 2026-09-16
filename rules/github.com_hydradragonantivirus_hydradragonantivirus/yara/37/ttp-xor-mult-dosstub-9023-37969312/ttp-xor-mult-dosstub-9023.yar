rule TTP_XOR_MULT_DOSStub_9023 {
  strings:
    $key_9023 = { c4 4b [2] b0 53 [2] f7 51 [2] b0 40 [2] fe 4c [2] f2 46 [2] e5 4d [2] fe 03 [2] c3 }

  condition:
    any of them
}