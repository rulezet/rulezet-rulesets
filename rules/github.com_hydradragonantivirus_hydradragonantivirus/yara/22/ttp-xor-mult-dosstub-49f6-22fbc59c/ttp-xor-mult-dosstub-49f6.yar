rule TTP_XOR_MULT_DOSStub_49f6 {
  strings:
    $key_49f6 = { 1d 9e [2] 69 86 [2] 2e 84 [2] 69 95 [2] 27 99 [2] 2b 93 [2] 3c 98 [2] 27 d6 [2] 1a }

  condition:
    any of them
}