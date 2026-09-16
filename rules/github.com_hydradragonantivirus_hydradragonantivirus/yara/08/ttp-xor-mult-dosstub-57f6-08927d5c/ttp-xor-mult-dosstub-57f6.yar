rule TTP_XOR_MULT_DOSStub_57f6 {
  strings:
    $key_57f6 = { 03 9e [2] 77 86 [2] 30 84 [2] 77 95 [2] 39 99 [2] 35 93 [2] 22 98 [2] 39 d6 [2] 04 }

  condition:
    any of them
}