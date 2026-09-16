rule TTP_XOR_MULT_DOSStub_00e9 {
  strings:
    $key_00e9 = { 54 81 [2] 20 99 [2] 67 9b [2] 20 8a [2] 6e 86 [2] 62 8c [2] 75 87 [2] 6e c9 [2] 53 }

  condition:
    any of them
}