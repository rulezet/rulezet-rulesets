rule TTP_XOR_MULT_DOSStub_912c {
  strings:
    $key_912c = { c5 44 [2] b1 5c [2] f6 5e [2] b1 4f [2] ff 43 [2] f3 49 [2] e4 42 [2] ff 0c [2] c2 }

  condition:
    any of them
}