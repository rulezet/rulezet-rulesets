rule TTP_XOR_MULT_DOSStub_6179 {
  strings:
    $key_6179 = { 35 11 [2] 41 09 [2] 06 0b [2] 41 1a [2] 0f 16 [2] 03 1c [2] 14 17 [2] 0f 59 [2] 32 }

  condition:
    any of them
}