rule TTP_XOR_MULT_DOSStub_47e5 {
  strings:
    $key_47e5 = { 13 8d [2] 67 95 [2] 20 97 [2] 67 86 [2] 29 8a [2] 25 80 [2] 32 8b [2] 29 c5 [2] 14 }

  condition:
    any of them
}