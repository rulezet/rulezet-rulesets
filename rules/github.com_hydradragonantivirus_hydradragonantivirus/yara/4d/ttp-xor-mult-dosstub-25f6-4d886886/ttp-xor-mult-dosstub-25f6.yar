rule TTP_XOR_MULT_DOSStub_25f6 {
  strings:
    $key_25f6 = { 71 9e [2] 05 86 [2] 42 84 [2] 05 95 [2] 4b 99 [2] 47 93 [2] 50 98 [2] 4b d6 [2] 76 }

  condition:
    any of them
}