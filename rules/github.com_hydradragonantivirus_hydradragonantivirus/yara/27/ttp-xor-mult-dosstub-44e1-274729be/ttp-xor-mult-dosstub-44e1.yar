rule TTP_XOR_MULT_DOSStub_44e1 {
  strings:
    $key_44e1 = { 10 89 [2] 64 91 [2] 23 93 [2] 64 82 [2] 2a 8e [2] 26 84 [2] 31 8f [2] 2a c1 [2] 17 }

  condition:
    any of them
}