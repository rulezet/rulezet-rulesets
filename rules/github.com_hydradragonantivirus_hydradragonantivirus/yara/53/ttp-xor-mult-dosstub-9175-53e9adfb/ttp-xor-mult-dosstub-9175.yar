rule TTP_XOR_MULT_DOSStub_9175 {
  strings:
    $key_9175 = { c5 1d [2] b1 05 [2] f6 07 [2] b1 16 [2] ff 1a [2] f3 10 [2] e4 1b [2] ff 55 [2] c2 }

  condition:
    any of them
}