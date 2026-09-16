rule TTP_XOR_MULT_DOSStub_1276 {
  strings:
    $key_1276 = { 46 1e [2] 32 06 [2] 75 04 [2] 32 15 [2] 7c 19 [2] 70 13 [2] 67 18 [2] 7c 56 [2] 41 }

  condition:
    any of them
}