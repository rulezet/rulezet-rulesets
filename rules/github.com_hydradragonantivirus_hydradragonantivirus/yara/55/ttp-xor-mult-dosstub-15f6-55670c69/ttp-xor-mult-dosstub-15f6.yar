rule TTP_XOR_MULT_DOSStub_15f6 {
  strings:
    $key_15f6 = { 41 9e [2] 35 86 [2] 72 84 [2] 35 95 [2] 7b 99 [2] 77 93 [2] 60 98 [2] 7b d6 [2] 46 }

  condition:
    any of them
}