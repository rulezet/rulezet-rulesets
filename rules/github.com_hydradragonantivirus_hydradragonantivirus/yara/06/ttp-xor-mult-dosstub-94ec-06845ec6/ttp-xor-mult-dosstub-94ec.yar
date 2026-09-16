rule TTP_XOR_MULT_DOSStub_94ec {
  strings:
    $key_94ec = { c0 84 [2] b4 9c [2] f3 9e [2] b4 8f [2] fa 83 [2] f6 89 [2] e1 82 [2] fa cc [2] c7 }

  condition:
    any of them
}