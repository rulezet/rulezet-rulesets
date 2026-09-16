rule TTP_XOR_MULT_DOSStub_3ef6 {
  strings:
    $key_3ef6 = { 6a 9e [2] 1e 86 [2] 59 84 [2] 1e 95 [2] 50 99 [2] 5c 93 [2] 4b 98 [2] 50 d6 [2] 6d }

  condition:
    any of them
}