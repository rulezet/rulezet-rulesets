rule TTP_XOR_MULT_DOSStub_68f6 {
  strings:
    $key_68f6 = { 3c 9e [2] 48 86 [2] 0f 84 [2] 48 95 [2] 06 99 [2] 0a 93 [2] 1d 98 [2] 06 d6 [2] 3b }

  condition:
    any of them
}