rule TTP_XOR_MULT_DOSStub_4178 {
  strings:
    $key_4178 = { 15 10 [2] 61 08 [2] 26 0a [2] 61 1b [2] 2f 17 [2] 23 1d [2] 34 16 [2] 2f 58 [2] 12 }

  condition:
    any of them
}