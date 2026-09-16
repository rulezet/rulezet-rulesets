rule TTP_XOR_MULT_DOSStub_0764 {
  strings:
    $key_0764 = { 53 0c [2] 27 14 [2] 60 16 [2] 27 07 [2] 69 0b [2] 65 01 [2] 72 0a [2] 69 44 [2] 54 }

  condition:
    any of them
}