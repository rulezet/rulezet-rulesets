rule TTP_XOR_MULT_DOSStub_9126 {
  strings:
    $key_9126 = { c5 4e [2] b1 56 [2] f6 54 [2] b1 45 [2] ff 49 [2] f3 43 [2] e4 48 [2] ff 06 [2] c2 }

  condition:
    any of them
}