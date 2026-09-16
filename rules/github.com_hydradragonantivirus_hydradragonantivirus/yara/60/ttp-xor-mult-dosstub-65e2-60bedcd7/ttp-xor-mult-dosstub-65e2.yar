rule TTP_XOR_MULT_DOSStub_65e2 {
  strings:
    $key_65e2 = { 31 8a [2] 45 92 [2] 02 90 [2] 45 81 [2] 0b 8d [2] 07 87 [2] 10 8c [2] 0b c2 [2] 36 }

  condition:
    any of them
}