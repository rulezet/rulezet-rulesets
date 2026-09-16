rule TTP_XOR_MULT_DOSStub_23e1 {
  strings:
    $key_23e1 = { 77 89 [2] 03 91 [2] 44 93 [2] 03 82 [2] 4d 8e [2] 41 84 [2] 56 8f [2] 4d c1 [2] 70 }

  condition:
    any of them
}