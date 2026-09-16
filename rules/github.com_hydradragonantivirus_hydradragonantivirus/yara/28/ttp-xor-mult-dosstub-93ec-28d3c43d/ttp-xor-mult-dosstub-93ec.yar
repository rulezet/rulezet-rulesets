rule TTP_XOR_MULT_DOSStub_93ec {
  strings:
    $key_93ec = { c7 84 [2] b3 9c [2] f4 9e [2] b3 8f [2] fd 83 [2] f1 89 [2] e6 82 [2] fd cc [2] c0 }

  condition:
    any of them
}