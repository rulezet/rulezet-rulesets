rule TTP_XOR_MULT_DOSStub_7418 {
  strings:
    $key_7418 = { 20 70 [2] 54 68 [2] 13 6a [2] 54 7b [2] 1a 77 [2] 16 7d [2] 01 76 [2] 1a 38 [2] 27 }

  condition:
    any of them
}