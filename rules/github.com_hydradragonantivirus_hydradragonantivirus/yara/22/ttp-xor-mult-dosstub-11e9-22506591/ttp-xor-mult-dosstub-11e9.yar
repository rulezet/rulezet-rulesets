rule TTP_XOR_MULT_DOSStub_11e9 {
  strings:
    $key_11e9 = { 45 81 [2] 31 99 [2] 76 9b [2] 31 8a [2] 7f 86 [2] 73 8c [2] 64 87 [2] 7f c9 [2] 42 }

  condition:
    any of them
}