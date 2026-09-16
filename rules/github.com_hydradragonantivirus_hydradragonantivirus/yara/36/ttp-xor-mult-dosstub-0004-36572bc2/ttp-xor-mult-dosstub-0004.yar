rule TTP_XOR_MULT_DOSStub_0004 {
  strings:
    $key_0004 = { 54 6c [2] 20 74 [2] 67 76 [2] 20 67 [2] 6e 6b [2] 62 61 [2] 75 6a [2] 6e 24 [2] 53 }

  condition:
    any of them
}