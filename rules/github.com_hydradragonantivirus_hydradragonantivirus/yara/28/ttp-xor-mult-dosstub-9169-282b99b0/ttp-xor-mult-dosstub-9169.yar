rule TTP_XOR_MULT_DOSStub_9169 {
  strings:
    $key_9169 = { c5 01 [2] b1 19 [2] f6 1b [2] b1 0a [2] ff 06 [2] f3 0c [2] e4 07 [2] ff 49 [2] c2 }

  condition:
    any of them
}