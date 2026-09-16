rule TTP_XOR_MULT_DOSStub_06e8 {
  strings:
    $key_06e8 = { 52 80 [2] 26 98 [2] 61 9a [2] 26 8b [2] 68 87 [2] 64 8d [2] 73 86 [2] 68 c8 [2] 55 }

  condition:
    any of them
}