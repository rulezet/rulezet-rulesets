rule TTP_XOR_MULT_DOSStub_4764 {
  strings:
    $key_4764 = { 13 0c [2] 67 14 [2] 20 16 [2] 67 07 [2] 29 0b [2] 25 01 [2] 32 0a [2] 29 44 [2] 14 }

  condition:
    any of them
}