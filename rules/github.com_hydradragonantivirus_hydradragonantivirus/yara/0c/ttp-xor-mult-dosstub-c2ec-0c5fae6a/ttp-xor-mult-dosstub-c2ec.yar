rule TTP_XOR_MULT_DOSStub_c2ec {
  strings:
    $key_c2ec = { 96 84 [2] e2 9c [2] a5 9e [2] e2 8f [2] ac 83 [2] a0 89 [2] b7 82 [2] ac cc [2] 91 }

  condition:
    any of them
}