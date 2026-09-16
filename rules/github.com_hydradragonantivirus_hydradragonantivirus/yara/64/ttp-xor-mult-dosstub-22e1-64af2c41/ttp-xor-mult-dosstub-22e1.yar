rule TTP_XOR_MULT_DOSStub_22e1 {
  strings:
    $key_22e1 = { 76 89 [2] 02 91 [2] 45 93 [2] 02 82 [2] 4c 8e [2] 40 84 [2] 57 8f [2] 4c c1 [2] 71 }

  condition:
    any of them
}