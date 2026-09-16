rule TTP_XOR_MULT_DOSStub_1664 {
  strings:
    $key_1664 = { 42 0c [2] 36 14 [2] 71 16 [2] 36 07 [2] 78 0b [2] 74 01 [2] 63 0a [2] 78 44 [2] 45 }

  condition:
    any of them
}