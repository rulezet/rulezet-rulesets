rule TTP_XOR_MULT_DOSStub_5d76 {
  strings:
    $key_5d76 = { 09 1e [2] 7d 06 [2] 3a 04 [2] 7d 15 [2] 33 19 [2] 3f 13 [2] 28 18 [2] 33 56 [2] 0e }

  condition:
    any of them
}