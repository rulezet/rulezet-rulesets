rule TTP_XOR_MULT_DOSStub_0504 {
  strings:
    $key_0504 = { 51 6c [2] 25 74 [2] 62 76 [2] 25 67 [2] 6b 6b [2] 67 61 [2] 70 6a [2] 6b 24 [2] 56 }

  condition:
    any of them
}