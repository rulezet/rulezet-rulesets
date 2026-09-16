rule TTP_XOR_MULT_DOSStub_0665 {
  strings:
    $key_0665 = { 52 0d [2] 26 15 [2] 61 17 [2] 26 06 [2] 68 0a [2] 64 00 [2] 73 0b [2] 68 45 [2] 55 }

  condition:
    any of them
}