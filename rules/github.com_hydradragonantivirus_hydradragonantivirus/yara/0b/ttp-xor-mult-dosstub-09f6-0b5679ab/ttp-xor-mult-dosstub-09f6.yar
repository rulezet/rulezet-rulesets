rule TTP_XOR_MULT_DOSStub_09f6 {
  strings:
    $key_09f6 = { 5d 9e [2] 29 86 [2] 6e 84 [2] 29 95 [2] 67 99 [2] 6b 93 [2] 7c 98 [2] 67 d6 [2] 5a }

  condition:
    any of them
}