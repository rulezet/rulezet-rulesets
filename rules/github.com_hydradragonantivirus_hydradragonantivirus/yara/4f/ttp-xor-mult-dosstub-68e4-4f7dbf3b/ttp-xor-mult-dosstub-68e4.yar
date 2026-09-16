rule TTP_XOR_MULT_DOSStub_68e4 {
  strings:
    $key_68e4 = { 3c 8c [2] 48 94 [2] 0f 96 [2] 48 87 [2] 06 8b [2] 0a 81 [2] 1d 8a [2] 06 c4 [2] 3b }

  condition:
    any of them
}