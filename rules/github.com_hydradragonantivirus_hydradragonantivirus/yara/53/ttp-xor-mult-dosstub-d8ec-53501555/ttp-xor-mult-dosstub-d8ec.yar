rule TTP_XOR_MULT_DOSStub_d8ec {
  strings:
    $key_d8ec = { 8c 84 [2] f8 9c [2] bf 9e [2] f8 8f [2] b6 83 [2] ba 89 [2] ad 82 [2] b6 cc [2] 8b }

  condition:
    any of them
}