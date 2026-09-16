rule TTP_XOR_MULT_DOSStub_e5ec {
  strings:
    $key_e5ec = { b1 84 [2] c5 9c [2] 82 9e [2] c5 8f [2] 8b 83 [2] 87 89 [2] 90 82 [2] 8b cc [2] b6 }

  condition:
    any of them
}