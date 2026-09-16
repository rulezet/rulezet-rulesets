rule TTP_XOR_MULT_DOSStub_0ff6 {
  strings:
    $key_0ff6 = { 5b 9e [2] 2f 86 [2] 68 84 [2] 2f 95 [2] 61 99 [2] 6d 93 [2] 7a 98 [2] 61 d6 [2] 5c }

  condition:
    any of them
}