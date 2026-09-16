rule TTP_XOR_MULT_DOSStub_9164 {
  strings:
    $key_9164 = { c5 0c [2] b1 14 [2] f6 16 [2] b1 07 [2] ff 0b [2] f3 01 [2] e4 0a [2] ff 44 [2] c2 }

  condition:
    any of them
}