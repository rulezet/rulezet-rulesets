rule TTP_XOR_MULT_DOSStub_952c {
  strings:
    $key_952c = { c1 44 [2] b5 5c [2] f2 5e [2] b5 4f [2] fb 43 [2] f7 49 [2] e0 42 [2] fb 0c [2] c6 }

  condition:
    any of them
}