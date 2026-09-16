rule TTP_XOR_MULT_DOSStub_0654 {
  strings:
    $key_0654 = { 52 3c [2] 26 24 [2] 61 26 [2] 26 37 [2] 68 3b [2] 64 31 [2] 73 3a [2] 68 74 [2] 55 }

  condition:
    any of them
}