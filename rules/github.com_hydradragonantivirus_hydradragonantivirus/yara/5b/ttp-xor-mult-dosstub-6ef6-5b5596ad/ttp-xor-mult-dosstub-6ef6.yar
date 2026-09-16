rule TTP_XOR_MULT_DOSStub_6ef6 {
  strings:
    $key_6ef6 = { 3a 9e [2] 4e 86 [2] 09 84 [2] 4e 95 [2] 00 99 [2] 0c 93 [2] 1b 98 [2] 00 d6 [2] 3d }

  condition:
    any of them
}