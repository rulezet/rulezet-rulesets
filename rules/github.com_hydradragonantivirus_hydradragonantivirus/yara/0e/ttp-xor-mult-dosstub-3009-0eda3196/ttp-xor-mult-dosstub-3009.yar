rule TTP_XOR_MULT_DOSStub_3009 {
  strings:
    $key_3009 = { 64 61 [2] 10 79 [2] 57 7b [2] 10 6a [2] 5e 66 [2] 52 6c [2] 45 67 [2] 5e 29 [2] 63 }

  condition:
    any of them
}