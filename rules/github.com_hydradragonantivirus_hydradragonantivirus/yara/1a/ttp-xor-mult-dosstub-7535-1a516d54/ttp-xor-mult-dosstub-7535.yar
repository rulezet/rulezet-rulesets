rule TTP_XOR_MULT_DOSStub_7535 {
  strings:
    $key_7535 = { 21 5d [2] 55 45 [2] 12 47 [2] 55 56 [2] 1b 5a [2] 17 50 [2] 00 5b [2] 1b 15 [2] 26 }

  condition:
    any of them
}