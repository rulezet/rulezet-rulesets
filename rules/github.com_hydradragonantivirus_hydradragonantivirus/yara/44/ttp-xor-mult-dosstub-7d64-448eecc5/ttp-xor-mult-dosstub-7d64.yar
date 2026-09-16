rule TTP_XOR_MULT_DOSStub_7d64 {
  strings:
    $key_7d64 = { 29 0c [2] 5d 14 [2] 1a 16 [2] 5d 07 [2] 13 0b [2] 1f 01 [2] 08 0a [2] 13 44 [2] 2e }

  condition:
    any of them
}