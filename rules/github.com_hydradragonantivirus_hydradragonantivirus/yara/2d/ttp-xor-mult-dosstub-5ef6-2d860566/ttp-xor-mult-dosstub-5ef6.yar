rule TTP_XOR_MULT_DOSStub_5ef6 {
  strings:
    $key_5ef6 = { 0a 9e [2] 7e 86 [2] 39 84 [2] 7e 95 [2] 30 99 [2] 3c 93 [2] 2b 98 [2] 30 d6 [2] 0d }

  condition:
    any of them
}