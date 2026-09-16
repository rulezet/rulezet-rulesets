rule TTP_XOR_MULT_DOSStub_5765 {
  strings:
    $key_5765 = { 03 0d [2] 77 15 [2] 30 17 [2] 77 06 [2] 39 0a [2] 35 00 [2] 22 0b [2] 39 45 [2] 04 }

  condition:
    any of them
}