rule TTP_XOR_MULT_DOSStub_9764 {
  strings:
    $key_9764 = { c3 0c [2] b7 14 [2] f0 16 [2] b7 07 [2] f9 0b [2] f5 01 [2] e2 0a [2] f9 44 [2] c4 }

  condition:
    any of them
}