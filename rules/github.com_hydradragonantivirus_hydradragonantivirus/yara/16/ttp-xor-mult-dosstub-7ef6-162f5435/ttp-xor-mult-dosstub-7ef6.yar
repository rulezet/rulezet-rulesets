rule TTP_XOR_MULT_DOSStub_7ef6 {
  strings:
    $key_7ef6 = { 2a 9e [2] 5e 86 [2] 19 84 [2] 5e 95 [2] 10 99 [2] 1c 93 [2] 0b 98 [2] 10 d6 [2] 2d }

  condition:
    any of them
}