rule TTP_XOR_MULT_DOSStub_1ef6 {
  strings:
    $key_1ef6 = { 4a 9e [2] 3e 86 [2] 79 84 [2] 3e 95 [2] 70 99 [2] 7c 93 [2] 6b 98 [2] 70 d6 [2] 4d }

  condition:
    any of them
}