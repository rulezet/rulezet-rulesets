rule TTP_XOR_MULT_DOSStub_9669 {
  strings:
    $key_9669 = { c2 01 [2] b6 19 [2] f1 1b [2] b6 0a [2] f8 06 [2] f4 0c [2] e3 07 [2] f8 49 [2] c5 }

  condition:
    any of them
}