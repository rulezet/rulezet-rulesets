rule TTP_XOR_MULT_DOSStub_6264 {
  strings:
    $key_6264 = { 36 0c [2] 42 14 [2] 05 16 [2] 42 07 [2] 0c 0b [2] 00 01 [2] 17 0a [2] 0c 44 [2] 31 }

  condition:
    any of them
}