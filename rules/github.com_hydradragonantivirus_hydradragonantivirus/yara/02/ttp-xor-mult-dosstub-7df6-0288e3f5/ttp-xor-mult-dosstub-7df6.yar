rule TTP_XOR_MULT_DOSStub_7df6 {
  strings:
    $key_7df6 = { 29 9e [2] 5d 86 [2] 1a 84 [2] 5d 95 [2] 13 99 [2] 1f 93 [2] 08 98 [2] 13 d6 [2] 2e }

  condition:
    any of them
}