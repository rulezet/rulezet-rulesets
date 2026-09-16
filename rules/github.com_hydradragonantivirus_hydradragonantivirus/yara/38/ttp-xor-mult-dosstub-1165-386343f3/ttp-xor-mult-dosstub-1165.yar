rule TTP_XOR_MULT_DOSStub_1165 {
  strings:
    $key_1165 = { 45 0d [2] 31 15 [2] 76 17 [2] 31 06 [2] 7f 0a [2] 73 00 [2] 64 0b [2] 7f 45 [2] 42 }

  condition:
    any of them
}