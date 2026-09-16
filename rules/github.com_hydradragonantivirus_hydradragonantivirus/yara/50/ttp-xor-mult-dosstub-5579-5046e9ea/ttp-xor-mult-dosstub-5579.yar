rule TTP_XOR_MULT_DOSStub_5579 {
  strings:
    $key_5579 = { 01 11 [2] 75 09 [2] 32 0b [2] 75 1a [2] 3b 16 [2] 37 1c [2] 20 17 [2] 3b 59 [2] 06 }

  condition:
    any of them
}