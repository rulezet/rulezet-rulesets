rule TTP_XOR_MULT_DOSStub_7664 {
  strings:
    $key_7664 = { 22 0c [2] 56 14 [2] 11 16 [2] 56 07 [2] 18 0b [2] 14 01 [2] 03 0a [2] 18 44 [2] 25 }

  condition:
    any of them
}