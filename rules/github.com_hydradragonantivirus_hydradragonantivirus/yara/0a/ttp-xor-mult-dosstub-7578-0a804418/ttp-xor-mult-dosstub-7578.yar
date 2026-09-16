rule TTP_XOR_MULT_DOSStub_7578 {
  strings:
    $key_7578 = { 21 10 [2] 55 08 [2] 12 0a [2] 55 1b [2] 1b 17 [2] 17 1d [2] 00 16 [2] 1b 58 [2] 26 }

  condition:
    any of them
}