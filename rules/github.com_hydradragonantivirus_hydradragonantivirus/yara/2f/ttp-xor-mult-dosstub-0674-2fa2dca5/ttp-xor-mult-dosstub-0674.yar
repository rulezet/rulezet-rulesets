rule TTP_XOR_MULT_DOSStub_0674 {
  strings:
    $key_0674 = { 52 1c [2] 26 04 [2] 61 06 [2] 26 17 [2] 68 1b [2] 64 11 [2] 73 1a [2] 68 54 [2] 55 }

  condition:
    any of them
}