rule TTP_XOR_MULT_DOSStub_1e76 {
  strings:
    $key_1e76 = { 4a 1e [2] 3e 06 [2] 79 04 [2] 3e 15 [2] 70 19 [2] 7c 13 [2] 6b 18 [2] 70 56 [2] 4d }

  condition:
    any of them
}