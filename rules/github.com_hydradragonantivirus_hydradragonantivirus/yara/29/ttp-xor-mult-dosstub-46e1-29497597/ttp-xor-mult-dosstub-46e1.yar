rule TTP_XOR_MULT_DOSStub_46e1 {
  strings:
    $key_46e1 = { 12 89 [2] 66 91 [2] 21 93 [2] 66 82 [2] 28 8e [2] 24 84 [2] 33 8f [2] 28 c1 [2] 15 }

  condition:
    any of them
}