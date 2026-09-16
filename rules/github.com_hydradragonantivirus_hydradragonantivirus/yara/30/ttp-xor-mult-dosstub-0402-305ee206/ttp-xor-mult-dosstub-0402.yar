rule TTP_XOR_MULT_DOSStub_0402 {
  strings:
    $key_0402 = { 50 6a [2] 24 72 [2] 63 70 [2] 24 61 [2] 6a 6d [2] 66 67 [2] 71 6c [2] 6a 22 [2] 57 }

  condition:
    any of them
}