rule TTP_XOR_MULT_DOSStub_947c {
  strings:
    $key_947c = { c0 14 [2] b4 0c [2] f3 0e [2] b4 1f [2] fa 13 [2] f6 19 [2] e1 12 [2] fa 5c [2] c7 }

  condition:
    any of them
}