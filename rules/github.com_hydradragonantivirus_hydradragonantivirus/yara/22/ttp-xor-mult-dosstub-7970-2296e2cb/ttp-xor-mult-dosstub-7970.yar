rule TTP_XOR_MULT_DOSStub_7970 {
  strings:
    $key_7970 = { 2d 18 [2] 59 00 [2] 1e 02 [2] 59 13 [2] 17 1f [2] 1b 15 [2] 0c 1e [2] 17 50 [2] 2a }

  condition:
    any of them
}