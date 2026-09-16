rule TTP_XOR_MULT_DOSStub_24f6 {
  strings:
    $key_24f6 = { 70 9e [2] 04 86 [2] 43 84 [2] 04 95 [2] 4a 99 [2] 46 93 [2] 51 98 [2] 4a d6 [2] 77 }

  condition:
    any of them
}