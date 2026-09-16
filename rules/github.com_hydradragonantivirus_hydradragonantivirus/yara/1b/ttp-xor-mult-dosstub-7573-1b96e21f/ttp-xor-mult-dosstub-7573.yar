rule TTP_XOR_MULT_DOSStub_7573 {
  strings:
    $key_7573 = { 21 1b [2] 55 03 [2] 12 01 [2] 55 10 [2] 1b 1c [2] 17 16 [2] 00 1d [2] 1b 53 [2] 26 }

  condition:
    any of them
}