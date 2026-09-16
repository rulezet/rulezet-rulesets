rule TTP_XOR_MULT_DOSStub_67e8 {
  strings:
    $key_67e8 = { 33 80 [2] 47 98 [2] 00 9a [2] 47 8b [2] 09 87 [2] 05 8d [2] 12 86 [2] 09 c8 [2] 34 }

  condition:
    any of them
}