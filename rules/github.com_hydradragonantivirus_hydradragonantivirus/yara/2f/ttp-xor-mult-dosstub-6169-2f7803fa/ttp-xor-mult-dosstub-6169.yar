rule TTP_XOR_MULT_DOSStub_6169 {
  strings:
    $key_6169 = { 35 01 [2] 41 19 [2] 06 1b [2] 41 0a [2] 0f 06 [2] 03 0c [2] 14 07 [2] 0f 49 [2] 32 }

  condition:
    any of them
}