rule TTP_XOR_MULT_DOSStub_7478 {
  strings:
    $key_7478 = { 20 10 [2] 54 08 [2] 13 0a [2] 54 1b [2] 1a 17 [2] 16 1d [2] 01 16 [2] 1a 58 [2] 27 }

  condition:
    any of them
}