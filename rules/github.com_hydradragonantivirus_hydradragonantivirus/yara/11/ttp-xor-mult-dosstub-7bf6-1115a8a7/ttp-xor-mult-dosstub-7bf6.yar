rule TTP_XOR_MULT_DOSStub_7bf6 {
  strings:
    $key_7bf6 = { 2f 9e [2] 5b 86 [2] 1c 84 [2] 5b 95 [2] 15 99 [2] 19 93 [2] 0e 98 [2] 15 d6 [2] 28 }

  condition:
    any of them
}