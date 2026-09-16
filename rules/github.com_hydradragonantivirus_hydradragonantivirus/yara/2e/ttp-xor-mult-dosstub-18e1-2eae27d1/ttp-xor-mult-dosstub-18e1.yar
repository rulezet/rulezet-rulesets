rule TTP_XOR_MULT_DOSStub_18e1 {
  strings:
    $key_18e1 = { 4c 89 [2] 38 91 [2] 7f 93 [2] 38 82 [2] 76 8e [2] 7a 84 [2] 6d 8f [2] 76 c1 [2] 4b }

  condition:
    any of them
}