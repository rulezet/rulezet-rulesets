rule TTP_XOR_MULT_DOSStub_d7ec {
  strings:
    $key_d7ec = { 83 84 [2] f7 9c [2] b0 9e [2] f7 8f [2] b9 83 [2] b5 89 [2] a2 82 [2] b9 cc [2] 84 }

  condition:
    any of them
}