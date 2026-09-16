rule TTP_XOR_MULT_DOSStub_6d64 {
  strings:
    $key_6d64 = { 39 0c [2] 4d 14 [2] 0a 16 [2] 4d 07 [2] 03 0b [2] 0f 01 [2] 18 0a [2] 03 44 [2] 3e }

  condition:
    any of them
}