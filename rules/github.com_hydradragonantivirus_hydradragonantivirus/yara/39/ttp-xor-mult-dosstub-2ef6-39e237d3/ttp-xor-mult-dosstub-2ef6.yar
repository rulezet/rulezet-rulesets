rule TTP_XOR_MULT_DOSStub_2ef6 {
  strings:
    $key_2ef6 = { 7a 9e [2] 0e 86 [2] 49 84 [2] 0e 95 [2] 40 99 [2] 4c 93 [2] 5b 98 [2] 40 d6 [2] 7d }

  condition:
    any of them
}