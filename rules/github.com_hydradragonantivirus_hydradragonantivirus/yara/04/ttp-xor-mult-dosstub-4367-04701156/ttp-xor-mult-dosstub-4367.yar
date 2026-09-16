rule TTP_XOR_MULT_DOSStub_4367 {
  strings:
    $key_4367 = { 17 0f [2] 63 17 [2] 24 15 [2] 63 04 [2] 2d 08 [2] 21 02 [2] 36 09 [2] 2d 47 [2] 10 }

  condition:
    any of them
}