rule TTP_XOR_MULT_DOSStub_9101 {
  strings:
    $key_9101 = { c5 69 [2] b1 71 [2] f6 73 [2] b1 62 [2] ff 6e [2] f3 64 [2] e4 6f [2] ff 21 [2] c2 }

  condition:
    any of them
}