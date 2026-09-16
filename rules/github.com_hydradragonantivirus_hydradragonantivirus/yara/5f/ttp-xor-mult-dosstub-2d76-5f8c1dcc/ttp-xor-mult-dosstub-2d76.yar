rule TTP_XOR_MULT_DOSStub_2d76 {
  strings:
    $key_2d76 = { 79 1e [2] 0d 06 [2] 4a 04 [2] 0d 15 [2] 43 19 [2] 4f 13 [2] 58 18 [2] 43 56 [2] 7e }

  condition:
    any of them
}