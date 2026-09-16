rule TTP_XOR_MULT_DOSStub_953c {
  strings:
    $key_953c = { c1 54 [2] b5 4c [2] f2 4e [2] b5 5f [2] fb 53 [2] f7 59 [2] e0 52 [2] fb 1c [2] c6 }

  condition:
    any of them
}