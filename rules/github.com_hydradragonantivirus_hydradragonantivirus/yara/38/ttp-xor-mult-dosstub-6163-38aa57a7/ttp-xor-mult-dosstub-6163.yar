rule TTP_XOR_MULT_DOSStub_6163 {
  strings:
    $key_6163 = { 35 0b [2] 41 13 [2] 06 11 [2] 41 00 [2] 0f 0c [2] 03 06 [2] 14 0d [2] 0f 43 [2] 32 }

  condition:
    any of them
}