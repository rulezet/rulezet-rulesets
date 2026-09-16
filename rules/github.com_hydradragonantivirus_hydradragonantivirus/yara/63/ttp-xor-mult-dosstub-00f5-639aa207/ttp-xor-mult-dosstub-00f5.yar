rule TTP_XOR_MULT_DOSStub_00f5 {
  strings:
    $key_00f5 = { 54 9d [2] 20 85 [2] 67 87 [2] 20 96 [2] 6e 9a [2] 62 90 [2] 75 9b [2] 6e d5 [2] 53 }

  condition:
    any of them
}