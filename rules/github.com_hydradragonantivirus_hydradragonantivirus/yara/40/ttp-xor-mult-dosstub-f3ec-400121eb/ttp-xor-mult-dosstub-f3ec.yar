rule TTP_XOR_MULT_DOSStub_f3ec {
  strings:
    $key_f3ec = { a7 84 [2] d3 9c [2] 94 9e [2] d3 8f [2] 9d 83 [2] 91 89 [2] 86 82 [2] 9d cc [2] a0 }

  condition:
    any of them
}