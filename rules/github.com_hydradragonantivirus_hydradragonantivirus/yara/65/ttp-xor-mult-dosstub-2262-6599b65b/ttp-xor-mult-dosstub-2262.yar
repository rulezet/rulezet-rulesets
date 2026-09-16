rule TTP_XOR_MULT_DOSStub_2262 {
  strings:
    $key_2262 = { 76 0a [2] 02 12 [2] 45 10 [2] 02 01 [2] 4c 0d [2] 40 07 [2] 57 0c [2] 4c 42 [2] 71 }

  condition:
    any of them
}