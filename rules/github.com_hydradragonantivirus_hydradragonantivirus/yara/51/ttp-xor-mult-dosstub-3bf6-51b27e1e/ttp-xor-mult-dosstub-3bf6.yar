rule TTP_XOR_MULT_DOSStub_3bf6 {
  strings:
    $key_3bf6 = { 6f 9e [2] 1b 86 [2] 5c 84 [2] 1b 95 [2] 55 99 [2] 59 93 [2] 4e 98 [2] 55 d6 [2] 68 }

  condition:
    any of them
}