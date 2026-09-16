rule TTP_XOR_MULT_DOSStub_d6ec {
  strings:
    $key_d6ec = { 82 84 [2] f6 9c [2] b1 9e [2] f6 8f [2] b8 83 [2] b4 89 [2] a3 82 [2] b8 cc [2] 85 }

  condition:
    any of them
}