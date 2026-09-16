rule TTP_XOR_MULT_DOSStub_95ec {
  strings:
    $key_95ec = { c1 84 [2] b5 9c [2] f2 9e [2] b5 8f [2] fb 83 [2] f7 89 [2] e0 82 [2] fb cc [2] c6 }

  condition:
    any of them
}