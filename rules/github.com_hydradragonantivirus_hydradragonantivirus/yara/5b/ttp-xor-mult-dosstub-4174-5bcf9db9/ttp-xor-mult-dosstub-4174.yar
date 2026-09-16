rule TTP_XOR_MULT_DOSStub_4174 {
  strings:
    $key_4174 = { 15 1c [2] 61 04 [2] 26 06 [2] 61 17 [2] 2f 1b [2] 23 11 [2] 34 1a [2] 2f 54 [2] 12 }

  condition:
    any of them
}