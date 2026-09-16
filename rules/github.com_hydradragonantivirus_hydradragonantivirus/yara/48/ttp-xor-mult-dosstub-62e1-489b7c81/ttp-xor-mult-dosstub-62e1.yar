rule TTP_XOR_MULT_DOSStub_62e1 {
  strings:
    $key_62e1 = { 36 89 [2] 42 91 [2] 05 93 [2] 42 82 [2] 0c 8e [2] 00 84 [2] 17 8f [2] 0c c1 [2] 31 }

  condition:
    any of them
}