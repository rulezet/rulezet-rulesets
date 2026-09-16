rule TTP_XOR_MULT_DOSStub_6139 {
  strings:
    $key_6139 = { 35 51 [2] 41 49 [2] 06 4b [2] 41 5a [2] 0f 56 [2] 03 5c [2] 14 57 [2] 0f 19 [2] 32 }

  condition:
    any of them
}