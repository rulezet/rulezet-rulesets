rule TTP_XOR_MULT_DOSStub_4104 {
  strings:
    $key_4104 = { 15 6c [2] 61 74 [2] 26 76 [2] 61 67 [2] 2f 6b [2] 23 61 [2] 34 6a [2] 2f 24 [2] 12 }

  condition:
    any of them
}