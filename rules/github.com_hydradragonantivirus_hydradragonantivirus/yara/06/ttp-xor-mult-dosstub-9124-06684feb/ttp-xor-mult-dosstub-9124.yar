rule TTP_XOR_MULT_DOSStub_9124 {
  strings:
    $key_9124 = { c5 4c [2] b1 54 [2] f6 56 [2] b1 47 [2] ff 4b [2] f3 41 [2] e4 4a [2] ff 04 [2] c2 }

  condition:
    any of them
}