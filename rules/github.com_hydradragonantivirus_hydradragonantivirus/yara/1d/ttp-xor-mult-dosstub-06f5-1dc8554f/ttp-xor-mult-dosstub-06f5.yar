rule TTP_XOR_MULT_DOSStub_06f5 {
  strings:
    $key_06f5 = { 52 9d [2] 26 85 [2] 61 87 [2] 26 96 [2] 68 9a [2] 64 90 [2] 73 9b [2] 68 d5 [2] 55 }

  condition:
    any of them
}