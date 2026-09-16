rule TTP_XOR_MULT_DOSStub_1162 {
  strings:
    $key_1162 = { 45 0a [2] 31 12 [2] 76 10 [2] 31 01 [2] 7f 0d [2] 73 07 [2] 64 0c [2] 7f 42 [2] 42 }

  condition:
    any of them
}