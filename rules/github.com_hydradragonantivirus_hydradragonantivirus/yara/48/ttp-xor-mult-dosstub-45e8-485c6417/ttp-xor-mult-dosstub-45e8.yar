rule TTP_XOR_MULT_DOSStub_45e8 {
  strings:
    $key_45e8 = { 11 80 [2] 65 98 [2] 22 9a [2] 65 8b [2] 2b 87 [2] 27 8d [2] 30 86 [2] 2b c8 [2] 16 }

  condition:
    any of them
}