rule TTP_XOR_MULT_DOSStub_cfb7 {
  strings:
    $key_cfb7 = { 9b df [2] ef c7 [2] a8 c5 [2] ef d4 [2] a1 d8 [2] ad d2 [2] ba d9 [2] a1 97 [2] 9c }

  condition:
    any of them
}