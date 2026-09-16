rule TTP_XOR_MULT_DOSStub_902b {
  strings:
    $key_902b = { c4 43 [2] b0 5b [2] f7 59 [2] b0 48 [2] fe 44 [2] f2 4e [2] e5 45 [2] fe 0b [2] c3 }

  condition:
    any of them
}