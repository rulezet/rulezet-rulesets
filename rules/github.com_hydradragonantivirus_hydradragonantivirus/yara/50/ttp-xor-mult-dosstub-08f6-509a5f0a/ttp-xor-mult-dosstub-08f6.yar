rule TTP_XOR_MULT_DOSStub_08f6 {
  strings:
    $key_08f6 = { 5c 9e [2] 28 86 [2] 6f 84 [2] 28 95 [2] 66 99 [2] 6a 93 [2] 7d 98 [2] 66 d6 [2] 5b }

  condition:
    any of them
}