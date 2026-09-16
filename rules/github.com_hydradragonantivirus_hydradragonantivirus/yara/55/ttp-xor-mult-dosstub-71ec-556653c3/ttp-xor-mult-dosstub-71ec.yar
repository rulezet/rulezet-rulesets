rule TTP_XOR_MULT_DOSStub_71ec {
  strings:
    $key_71ec = { 25 84 [2] 51 9c [2] 16 9e [2] 51 8f [2] 1f 83 [2] 13 89 [2] 04 82 [2] 1f cc [2] 22 }

  condition:
    any of them
}