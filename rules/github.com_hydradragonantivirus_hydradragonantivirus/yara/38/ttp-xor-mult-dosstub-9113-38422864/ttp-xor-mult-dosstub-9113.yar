rule TTP_XOR_MULT_DOSStub_9113 {
  strings:
    $key_9113 = { c5 7b [2] b1 63 [2] f6 61 [2] b1 70 [2] ff 7c [2] f3 76 [2] e4 7d [2] ff 33 [2] c2 }

  condition:
    any of them
}