rule TTP_XOR_MULT_DOSStub_f1ec {
  strings:
    $key_f1ec = { a5 84 [2] d1 9c [2] 96 9e [2] d1 8f [2] 9f 83 [2] 93 89 [2] 84 82 [2] 9f cc [2] a2 }

  condition:
    any of them
}