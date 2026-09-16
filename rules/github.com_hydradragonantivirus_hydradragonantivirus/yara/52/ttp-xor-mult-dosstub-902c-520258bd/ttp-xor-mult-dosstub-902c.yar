rule TTP_XOR_MULT_DOSStub_902c {
  strings:
    $key_902c = { c4 44 [2] b0 5c [2] f7 5e [2] b0 4f [2] fe 43 [2] f2 49 [2] e5 42 [2] fe 0c [2] c3 }

  condition:
    any of them
}