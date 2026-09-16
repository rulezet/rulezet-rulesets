rule TTP_XOR_MULT_DOSStub_5bf6 {
  strings:
    $key_5bf6 = { 0f 9e [2] 7b 86 [2] 3c 84 [2] 7b 95 [2] 35 99 [2] 39 93 [2] 2e 98 [2] 35 d6 [2] 08 }

  condition:
    any of them
}