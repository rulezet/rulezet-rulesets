rule TTP_XOR_MULT_DOSStub_77e1 {
  strings:
    $key_77e1 = { 23 89 [2] 57 91 [2] 10 93 [2] 57 82 [2] 19 8e [2] 15 84 [2] 02 8f [2] 19 c1 [2] 24 }

  condition:
    any of them
}