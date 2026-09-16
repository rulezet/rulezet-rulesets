rule TTP_XOR_MULT_DOSStub_7528 {
  strings:
    $key_7528 = { 21 40 [2] 55 58 [2] 12 5a [2] 55 4b [2] 1b 47 [2] 17 4d [2] 00 46 [2] 1b 08 [2] 26 }

  condition:
    any of them
}