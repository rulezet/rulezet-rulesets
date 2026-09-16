rule TTP_XOR_MULT_DOSStub_25e9 {
  strings:
    $key_25e9 = { 71 81 [2] 05 99 [2] 42 9b [2] 05 8a [2] 4b 86 [2] 47 8c [2] 50 87 [2] 4b c9 [2] 76 }

  condition:
    any of them
}