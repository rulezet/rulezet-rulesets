rule TTP_XOR_MULT_DOSStub_0662 {
  strings:
    $key_0662 = { 52 0a [2] 26 12 [2] 61 10 [2] 26 01 [2] 68 0d [2] 64 07 [2] 73 0c [2] 68 42 [2] 55 }

  condition:
    any of them
}