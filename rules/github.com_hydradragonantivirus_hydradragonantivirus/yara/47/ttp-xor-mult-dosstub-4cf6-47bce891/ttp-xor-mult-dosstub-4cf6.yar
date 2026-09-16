rule TTP_XOR_MULT_DOSStub_4cf6 {
  strings:
    $key_4cf6 = { 18 9e [2] 6c 86 [2] 2b 84 [2] 6c 95 [2] 22 99 [2] 2e 93 [2] 39 98 [2] 22 d6 [2] 1f }

  condition:
    any of them
}