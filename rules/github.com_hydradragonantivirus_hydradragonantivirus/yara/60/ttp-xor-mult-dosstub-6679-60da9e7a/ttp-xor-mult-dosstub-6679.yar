rule TTP_XOR_MULT_DOSStub_6679 {
  strings:
    $key_6679 = { 32 11 [2] 46 09 [2] 01 0b [2] 46 1a [2] 08 16 [2] 04 1c [2] 13 17 [2] 08 59 [2] 35 }

  condition:
    any of them
}