rule TTP_XOR_MULT_DOSStub_7524 {
  strings:
    $key_7524 = { 21 4c [2] 55 54 [2] 12 56 [2] 55 47 [2] 1b 4b [2] 17 41 [2] 00 4a [2] 1b 04 [2] 26 }

  condition:
    any of them
}