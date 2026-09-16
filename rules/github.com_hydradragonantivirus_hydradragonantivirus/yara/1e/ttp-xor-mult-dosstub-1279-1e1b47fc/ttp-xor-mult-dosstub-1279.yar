rule TTP_XOR_MULT_DOSStub_1279 {
  strings:
    $key_1279 = { 46 11 [2] 32 09 [2] 75 0b [2] 32 1a [2] 7c 16 [2] 70 1c [2] 67 17 [2] 7c 59 [2] 41 }

  condition:
    any of them
}