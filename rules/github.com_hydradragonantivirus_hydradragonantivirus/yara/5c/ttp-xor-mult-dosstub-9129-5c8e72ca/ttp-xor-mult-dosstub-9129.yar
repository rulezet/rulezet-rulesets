rule TTP_XOR_MULT_DOSStub_9129 {
  strings:
    $key_9129 = { c5 41 [2] b1 59 [2] f6 5b [2] b1 4a [2] ff 46 [2] f3 4c [2] e4 47 [2] ff 09 [2] c2 }

  condition:
    any of them
}