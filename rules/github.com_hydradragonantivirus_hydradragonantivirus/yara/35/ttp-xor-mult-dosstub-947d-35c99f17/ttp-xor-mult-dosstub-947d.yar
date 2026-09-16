rule TTP_XOR_MULT_DOSStub_947d {
  strings:
    $key_947d = { c0 15 [2] b4 0d [2] f3 0f [2] b4 1e [2] fa 12 [2] f6 18 [2] e1 13 [2] fa 5d [2] c7 }

  condition:
    any of them
}