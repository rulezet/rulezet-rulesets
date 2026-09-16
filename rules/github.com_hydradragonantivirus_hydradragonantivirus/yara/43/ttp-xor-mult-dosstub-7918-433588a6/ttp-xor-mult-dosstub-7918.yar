rule TTP_XOR_MULT_DOSStub_7918 {
  strings:
    $key_7918 = { 2d 70 [2] 59 68 [2] 1e 6a [2] 59 7b [2] 17 77 [2] 1b 7d [2] 0c 76 [2] 17 38 [2] 2a }

  condition:
    any of them
}