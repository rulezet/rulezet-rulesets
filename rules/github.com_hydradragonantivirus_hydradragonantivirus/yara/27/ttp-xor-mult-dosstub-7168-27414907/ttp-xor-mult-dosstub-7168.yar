rule TTP_XOR_MULT_DOSStub_7168 {
  strings:
    $key_7168 = { 25 00 [2] 51 18 [2] 16 1a [2] 51 0b [2] 1f 07 [2] 13 0d [2] 04 06 [2] 1f 48 [2] 22 }

  condition:
    any of them
}