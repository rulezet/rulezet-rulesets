rule TTP_XOR_MULT_DOSStub_6265 {
  strings:
    $key_6265 = { 36 0d [2] 42 15 [2] 05 17 [2] 42 06 [2] 0c 0a [2] 00 00 [2] 17 0b [2] 0c 45 [2] 31 }

  condition:
    any of them
}