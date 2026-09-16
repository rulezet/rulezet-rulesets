rule TTP_XOR_MULT_DOSStub_11f5 {
  strings:
    $key_11f5 = { 45 9d [2] 31 85 [2] 76 87 [2] 31 96 [2] 7f 9a [2] 73 90 [2] 64 9b [2] 7f d5 [2] 42 }

  condition:
    any of them
}