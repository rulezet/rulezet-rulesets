rule TTP_XOR_MULT_DOSStub_9148 {
  strings:
    $key_9148 = { c5 20 [2] b1 38 [2] f6 3a [2] b1 2b [2] ff 27 [2] f3 2d [2] e4 26 [2] ff 68 [2] c2 }

  condition:
    any of them
}