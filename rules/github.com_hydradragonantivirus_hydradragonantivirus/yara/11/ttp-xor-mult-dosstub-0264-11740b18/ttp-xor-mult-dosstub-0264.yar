rule TTP_XOR_MULT_DOSStub_0264 {
  strings:
    $key_0264 = { 56 0c [2] 22 14 [2] 65 16 [2] 22 07 [2] 6c 0b [2] 60 01 [2] 77 0a [2] 6c 44 [2] 51 }

  condition:
    any of them
}