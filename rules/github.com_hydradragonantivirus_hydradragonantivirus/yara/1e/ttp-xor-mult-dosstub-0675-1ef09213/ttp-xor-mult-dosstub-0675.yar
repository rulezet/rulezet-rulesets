rule TTP_XOR_MULT_DOSStub_0675 {
  strings:
    $key_0675 = { 52 1d [2] 26 05 [2] 61 07 [2] 26 16 [2] 68 1a [2] 64 10 [2] 73 1b [2] 68 55 [2] 55 }

  condition:
    any of them
}