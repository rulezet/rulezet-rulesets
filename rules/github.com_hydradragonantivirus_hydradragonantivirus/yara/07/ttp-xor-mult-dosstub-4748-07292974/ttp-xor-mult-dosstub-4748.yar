rule TTP_XOR_MULT_DOSStub_4748 {
  strings:
    $key_4748 = { 13 20 [2] 67 38 [2] 20 3a [2] 67 2b [2] 29 27 [2] 25 2d [2] 32 26 [2] 29 68 [2] 14 }

  condition:
    any of them
}