rule TTP_XOR_MULT_DOSStub_4df6 {
  strings:
    $key_4df6 = { 19 9e [2] 6d 86 [2] 2a 84 [2] 6d 95 [2] 23 99 [2] 2f 93 [2] 38 98 [2] 23 d6 [2] 1e }

  condition:
    any of them
}