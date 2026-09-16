rule TTP_XOR_MULT_DOSStub_76e1 {
  strings:
    $key_76e1 = { 22 89 [2] 56 91 [2] 11 93 [2] 56 82 [2] 18 8e [2] 14 84 [2] 03 8f [2] 18 c1 [2] 25 }

  condition:
    any of them
}