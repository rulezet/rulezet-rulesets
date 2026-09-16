rule TTP_XOR_MULT_DOSStub_1168 {
  strings:
    $key_1168 = { 45 00 [2] 31 18 [2] 76 1a [2] 31 0b [2] 7f 07 [2] 73 0d [2] 64 06 [2] 7f 48 [2] 42 }

  condition:
    any of them
}