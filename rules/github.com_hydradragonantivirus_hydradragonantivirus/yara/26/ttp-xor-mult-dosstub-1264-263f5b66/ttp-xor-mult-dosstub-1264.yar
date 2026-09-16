rule TTP_XOR_MULT_DOSStub_1264 {
  strings:
    $key_1264 = { 46 0c [2] 32 14 [2] 75 16 [2] 32 07 [2] 7c 0b [2] 70 01 [2] 67 0a [2] 7c 44 [2] 41 }

  condition:
    any of them
}