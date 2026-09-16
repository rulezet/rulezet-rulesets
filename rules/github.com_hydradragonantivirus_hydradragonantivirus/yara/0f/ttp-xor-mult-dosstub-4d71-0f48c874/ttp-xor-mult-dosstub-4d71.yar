rule TTP_XOR_MULT_DOSStub_4d71 {
  strings:
    $key_4d71 = { 19 19 [2] 6d 01 [2] 2a 03 [2] 6d 12 [2] 23 1e [2] 2f 14 [2] 38 1f [2] 23 51 [2] 1e }

  condition:
    any of them
}