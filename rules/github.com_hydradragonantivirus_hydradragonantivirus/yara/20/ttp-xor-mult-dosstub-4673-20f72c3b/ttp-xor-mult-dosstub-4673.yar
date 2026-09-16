rule TTP_XOR_MULT_DOSStub_4673 {
  strings:
    $key_4673 = { 12 1b [2] 66 03 [2] 21 01 [2] 66 10 [2] 28 1c [2] 24 16 [2] 33 1d [2] 28 53 [2] 15 }

  condition:
    any of them
}