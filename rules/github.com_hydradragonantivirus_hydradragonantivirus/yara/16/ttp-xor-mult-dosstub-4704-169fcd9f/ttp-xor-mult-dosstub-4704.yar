rule TTP_XOR_MULT_DOSStub_4704 {
  strings:
    $key_4704 = { 13 6c [2] 67 74 [2] 20 76 [2] 67 67 [2] 29 6b [2] 25 61 [2] 32 6a [2] 29 24 [2] 14 }

  condition:
    any of them
}