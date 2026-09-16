rule TTP_XOR_MULT_DOSStub_0179 {
  strings:
    $key_0179 = { 55 11 [2] 21 09 [2] 66 0b [2] 21 1a [2] 6f 16 [2] 63 1c [2] 74 17 [2] 6f 59 [2] 52 }

  condition:
    any of them
}