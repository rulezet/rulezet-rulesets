rule TTP_XOR_MULT_DOSStub_50e9 {
  strings:
    $key_50e9 = { 04 81 [2] 70 99 [2] 37 9b [2] 70 8a [2] 3e 86 [2] 32 8c [2] 25 87 [2] 3e c9 [2] 03 }

  condition:
    any of them
}