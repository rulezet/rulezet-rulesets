rule TTP_XOR_MULT_DOSStub_68f7 {
  strings:
    $key_68f7 = { 3c 9f [2] 48 87 [2] 0f 85 [2] 48 94 [2] 06 98 [2] 0a 92 [2] 1d 99 [2] 06 d7 [2] 3b }

  condition:
    any of them
}