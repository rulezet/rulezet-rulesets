rule TTP_XOR_MULT_DOSStub_0404 {
  strings:
    $key_0404 = { 50 6c [2] 24 74 [2] 63 76 [2] 24 67 [2] 6a 6b [2] 66 61 [2] 71 6a [2] 6a 24 [2] 57 }

  condition:
    any of them
}