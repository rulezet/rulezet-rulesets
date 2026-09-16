rule TTP_XOR_MULT_DOSStub_9122 {
  strings:
    $key_9122 = { c5 4a [2] b1 52 [2] f6 50 [2] b1 41 [2] ff 4d [2] f3 47 [2] e4 4c [2] ff 02 [2] c2 }

  condition:
    any of them
}