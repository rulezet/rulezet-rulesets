rule TTP_XOR_MULT_DOSStub_7674 {
  strings:
    $key_7674 = { 22 1c [2] 56 04 [2] 11 06 [2] 56 17 [2] 18 1b [2] 14 11 [2] 03 1a [2] 18 54 [2] 25 }

  condition:
    any of them
}