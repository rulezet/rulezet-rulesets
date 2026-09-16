rule TTP_XOR_MULT_DOSStub_75e1 {
  strings:
    $key_75e1 = { 21 89 [2] 55 91 [2] 12 93 [2] 55 82 [2] 1b 8e [2] 17 84 [2] 00 8f [2] 1b c1 [2] 26 }

  condition:
    any of them
}