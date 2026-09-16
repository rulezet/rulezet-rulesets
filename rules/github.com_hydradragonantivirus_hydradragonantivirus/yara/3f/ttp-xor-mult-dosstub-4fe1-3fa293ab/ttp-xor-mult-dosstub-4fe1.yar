rule TTP_XOR_MULT_DOSStub_4fe1 {
  strings:
    $key_4fe1 = { 1b 89 [2] 6f 91 [2] 28 93 [2] 6f 82 [2] 21 8e [2] 2d 84 [2] 3a 8f [2] 21 c1 [2] 1c }

  condition:
    any of them
}