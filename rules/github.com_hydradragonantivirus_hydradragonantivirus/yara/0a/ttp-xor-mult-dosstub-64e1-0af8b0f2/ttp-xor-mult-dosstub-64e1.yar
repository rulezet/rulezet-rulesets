rule TTP_XOR_MULT_DOSStub_64e1 {
  strings:
    $key_64e1 = { 30 89 [2] 44 91 [2] 03 93 [2] 44 82 [2] 0a 8e [2] 06 84 [2] 11 8f [2] 0a c1 [2] 37 }

  condition:
    any of them
}