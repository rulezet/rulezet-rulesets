rule TTP_XOR_MULT_DOSStub_3364 {
  strings:
    $key_3364 = { 67 0c [2] 13 14 [2] 54 16 [2] 13 07 [2] 5d 0b [2] 51 01 [2] 46 0a [2] 5d 44 [2] 60 }

  condition:
    any of them
}