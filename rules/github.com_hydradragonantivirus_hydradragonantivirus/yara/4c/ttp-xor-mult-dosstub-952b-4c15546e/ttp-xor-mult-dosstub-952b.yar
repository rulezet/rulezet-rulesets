rule TTP_XOR_MULT_DOSStub_952b {
  strings:
    $key_952b = { c1 43 [2] b5 5b [2] f2 59 [2] b5 48 [2] fb 44 [2] f7 4e [2] e0 45 [2] fb 0b [2] c6 }

  condition:
    any of them
}