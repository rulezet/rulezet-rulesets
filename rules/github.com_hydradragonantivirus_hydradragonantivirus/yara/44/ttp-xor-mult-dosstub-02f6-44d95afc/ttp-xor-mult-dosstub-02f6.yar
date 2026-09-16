rule TTP_XOR_MULT_DOSStub_02f6 {
  strings:
    $key_02f6 = { 56 9e [2] 22 86 [2] 65 84 [2] 22 95 [2] 6c 99 [2] 60 93 [2] 77 98 [2] 6c d6 [2] 51 }

  condition:
    any of them
}