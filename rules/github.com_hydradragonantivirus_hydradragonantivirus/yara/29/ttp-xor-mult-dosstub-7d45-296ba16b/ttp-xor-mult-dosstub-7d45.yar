rule TTP_XOR_MULT_DOSStub_7d45 {
  strings:
    $key_7d45 = { 29 2d [2] 5d 35 [2] 1a 37 [2] 5d 26 [2] 13 2a [2] 1f 20 [2] 08 2b [2] 13 65 [2] 2e }

  condition:
    any of them
}