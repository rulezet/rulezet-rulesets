rule TTP_XOR_MULT_DOSStub_7569 {
  strings:
    $key_7569 = { 21 01 [2] 55 19 [2] 12 1b [2] 55 0a [2] 1b 06 [2] 17 0c [2] 00 07 [2] 1b 49 [2] 26 }

  condition:
    any of them
}