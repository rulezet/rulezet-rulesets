rule TTP_XOR_MULT_DOSStub_75e5 {
  strings:
    $key_75e5 = { 21 8d [2] 55 95 [2] 12 97 [2] 55 86 [2] 1b 8a [2] 17 80 [2] 00 8b [2] 1b c5 [2] 26 }

  condition:
    any of them
}