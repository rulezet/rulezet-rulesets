rule TTP_XOR_MULT_DOSStub_7d18 {
  strings:
    $key_7d18 = { 29 70 [2] 5d 68 [2] 1a 6a [2] 5d 7b [2] 13 77 [2] 1f 7d [2] 08 76 [2] 13 38 [2] 2e }

  condition:
    any of them
}