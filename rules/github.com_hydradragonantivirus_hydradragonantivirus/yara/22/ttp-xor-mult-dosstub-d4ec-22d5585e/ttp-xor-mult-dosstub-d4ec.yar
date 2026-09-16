rule TTP_XOR_MULT_DOSStub_d4ec {
  strings:
    $key_d4ec = { 80 84 [2] f4 9c [2] b3 9e [2] f4 8f [2] ba 83 [2] b6 89 [2] a1 82 [2] ba cc [2] 87 }

  condition:
    any of them
}