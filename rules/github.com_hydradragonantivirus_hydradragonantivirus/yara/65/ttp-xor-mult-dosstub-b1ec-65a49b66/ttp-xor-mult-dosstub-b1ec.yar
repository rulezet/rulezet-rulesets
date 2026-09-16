rule TTP_XOR_MULT_DOSStub_b1ec {
  strings:
    $key_b1ec = { e5 84 [2] 91 9c [2] d6 9e [2] 91 8f [2] df 83 [2] d3 89 [2] c4 82 [2] df cc [2] e2 }

  condition:
    any of them
}