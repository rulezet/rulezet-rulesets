rule TTP_XOR_MULT_DOSStub_0659 {
  strings:
    $key_0659 = { 52 31 [2] 26 29 [2] 61 2b [2] 26 3a [2] 68 36 [2] 64 3c [2] 73 37 [2] 68 79 [2] 55 }

  condition:
    any of them
}