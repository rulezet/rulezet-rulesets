rule TTP_XOR_MULT_DOSStub_914b {
  strings:
    $key_914b = { c5 23 [2] b1 3b [2] f6 39 [2] b1 28 [2] ff 24 [2] f3 2e [2] e4 25 [2] ff 6b [2] c2 }

  condition:
    any of them
}