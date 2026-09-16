rule TTP_XOR_MULT_DOSStub_32e1 {
  strings:
    $key_32e1 = { 66 89 [2] 12 91 [2] 55 93 [2] 12 82 [2] 5c 8e [2] 50 84 [2] 47 8f [2] 5c c1 [2] 61 }

  condition:
    any of them
}