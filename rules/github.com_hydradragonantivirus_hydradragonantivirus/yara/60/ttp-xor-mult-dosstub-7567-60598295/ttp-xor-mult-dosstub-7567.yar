rule TTP_XOR_MULT_DOSStub_7567 {
  strings:
    $key_7567 = { 21 0f [2] 55 17 [2] 12 15 [2] 55 04 [2] 1b 08 [2] 17 02 [2] 00 09 [2] 1b 47 [2] 26 }

  condition:
    any of them
}