rule TTP_XOR_MULT_DOSStub_3af6 {
  strings:
    $key_3af6 = { 6e 9e [2] 1a 86 [2] 5d 84 [2] 1a 95 [2] 54 99 [2] 58 93 [2] 4f 98 [2] 54 d6 [2] 69 }

  condition:
    any of them
}