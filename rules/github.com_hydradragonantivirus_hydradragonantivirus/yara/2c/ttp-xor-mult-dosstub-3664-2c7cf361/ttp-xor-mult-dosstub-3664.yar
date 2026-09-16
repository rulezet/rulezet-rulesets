rule TTP_XOR_MULT_DOSStub_3664 {
  strings:
    $key_3664 = { 62 0c [2] 16 14 [2] 51 16 [2] 16 07 [2] 58 0b [2] 54 01 [2] 43 0a [2] 58 44 [2] 65 }

  condition:
    any of them
}