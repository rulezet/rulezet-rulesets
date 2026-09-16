rule TTP_XOR_MULT_DOSStub_63e8 {
  strings:
    $key_63e8 = { 37 80 [2] 43 98 [2] 04 9a [2] 43 8b [2] 0d 87 [2] 01 8d [2] 16 86 [2] 0d c8 [2] 30 }

  condition:
    any of them
}