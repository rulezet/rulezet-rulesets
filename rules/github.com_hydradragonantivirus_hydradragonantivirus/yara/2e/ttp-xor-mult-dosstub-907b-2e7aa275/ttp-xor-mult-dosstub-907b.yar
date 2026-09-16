rule TTP_XOR_MULT_DOSStub_907b {
  strings:
    $key_907b = { c4 13 [2] b0 0b [2] f7 09 [2] b0 18 [2] fe 14 [2] f2 1e [2] e5 15 [2] fe 5b [2] c3 }

  condition:
    any of them
}