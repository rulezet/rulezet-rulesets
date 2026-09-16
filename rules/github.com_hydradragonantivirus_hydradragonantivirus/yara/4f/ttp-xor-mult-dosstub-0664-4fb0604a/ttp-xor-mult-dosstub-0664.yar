rule TTP_XOR_MULT_DOSStub_0664 {
  strings:
    $key_0664 = { 52 0c [2] 26 14 [2] 61 16 [2] 26 07 [2] 68 0b [2] 64 01 [2] 73 0a [2] 68 44 [2] 55 }

  condition:
    any of them
}