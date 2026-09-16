rule TTP_XOR_MULT_DOSStub_6154 {
  strings:
    $key_6154 = { 35 3c [2] 41 24 [2] 06 26 [2] 41 37 [2] 0f 3b [2] 03 31 [2] 14 3a [2] 0f 74 [2] 32 }

  condition:
    any of them
}