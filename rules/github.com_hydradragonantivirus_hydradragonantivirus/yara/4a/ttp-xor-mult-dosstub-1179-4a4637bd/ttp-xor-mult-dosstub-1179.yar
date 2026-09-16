rule TTP_XOR_MULT_DOSStub_1179 {
  strings:
    $key_1179 = { 45 11 [2] 31 09 [2] 76 0b [2] 31 1a [2] 7f 16 [2] 73 1c [2] 64 17 [2] 7f 59 [2] 42 }

  condition:
    any of them
}