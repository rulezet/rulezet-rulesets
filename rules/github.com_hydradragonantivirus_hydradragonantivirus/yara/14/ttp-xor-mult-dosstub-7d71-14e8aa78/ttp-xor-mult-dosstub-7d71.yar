rule TTP_XOR_MULT_DOSStub_7d71 {
  strings:
    $key_7d71 = { 29 19 [2] 5d 01 [2] 1a 03 [2] 5d 12 [2] 13 1e [2] 1f 14 [2] 08 1f [2] 13 51 [2] 2e }

  condition:
    any of them
}