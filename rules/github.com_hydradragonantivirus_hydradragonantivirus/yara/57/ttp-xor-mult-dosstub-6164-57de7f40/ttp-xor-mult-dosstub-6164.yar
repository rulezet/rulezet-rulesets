rule TTP_XOR_MULT_DOSStub_6164 {
  strings:
    $key_6164 = { 35 0c [2] 41 14 [2] 06 16 [2] 41 07 [2] 0f 0b [2] 03 01 [2] 14 0a [2] 0f 44 [2] 32 }

  condition:
    any of them
}