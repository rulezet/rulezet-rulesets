rule TTP_XOR_MULT_DOSStub_3164 {
  strings:
    $key_3164 = { 65 0c [2] 11 14 [2] 56 16 [2] 11 07 [2] 5f 0b [2] 53 01 [2] 44 0a [2] 5f 44 [2] 62 }

  condition:
    any of them
}