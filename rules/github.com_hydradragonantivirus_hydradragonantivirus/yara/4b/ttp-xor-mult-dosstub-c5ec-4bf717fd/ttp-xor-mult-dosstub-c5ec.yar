rule TTP_XOR_MULT_DOSStub_c5ec {
  strings:
    $key_c5ec = { 91 84 [2] e5 9c [2] a2 9e [2] e5 8f [2] ab 83 [2] a7 89 [2] b0 82 [2] ab cc [2] 96 }

  condition:
    any of them
}