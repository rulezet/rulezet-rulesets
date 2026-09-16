rule TTP_XOR_MULT_DOSStub_65e4 {
  strings:
    $key_65e4 = { 31 8c [2] 45 94 [2] 02 96 [2] 45 87 [2] 0b 8b [2] 07 81 [2] 10 8a [2] 0b c4 [2] 36 }

  condition:
    any of them
}