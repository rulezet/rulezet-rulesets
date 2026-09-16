rule TTP_XOR_MULT_DOSStub_68e2 {
  strings:
    $key_68e2 = { 3c 8a [2] 48 92 [2] 0f 90 [2] 48 81 [2] 06 8d [2] 0a 87 [2] 1d 8c [2] 06 c2 [2] 3b }

  condition:
    any of them
}