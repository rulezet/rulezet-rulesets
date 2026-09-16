rule TTP_XOR_MULT_DOSStub_3509 {
  strings:
    $key_3509 = { 61 61 [2] 15 79 [2] 52 7b [2] 15 6a [2] 5b 66 [2] 57 6c [2] 40 67 [2] 5b 29 [2] 66 }

  condition:
    any of them
}