rule TTP_XOR_MULT_DOSStub_6104 {
  strings:
    $key_6104 = { 35 6c [2] 41 74 [2] 06 76 [2] 41 67 [2] 0f 6b [2] 03 61 [2] 14 6a [2] 0f 24 [2] 32 }

  condition:
    any of them
}