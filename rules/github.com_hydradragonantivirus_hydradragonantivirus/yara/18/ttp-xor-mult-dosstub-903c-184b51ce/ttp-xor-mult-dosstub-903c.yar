rule TTP_XOR_MULT_DOSStub_903c {
  strings:
    $key_903c = { c4 54 [2] b0 4c [2] f7 4e [2] b0 5f [2] fe 53 [2] f2 59 [2] e5 52 [2] fe 1c [2] c3 }

  condition:
    any of them
}