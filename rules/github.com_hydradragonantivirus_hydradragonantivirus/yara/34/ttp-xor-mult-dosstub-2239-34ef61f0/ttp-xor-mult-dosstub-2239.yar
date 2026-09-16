rule TTP_XOR_MULT_DOSStub_2239 {
  strings:
    $key_2239 = { 76 51 [2] 02 49 [2] 45 4b [2] 02 5a [2] 4c 56 [2] 40 5c [2] 57 57 [2] 4c 19 [2] 71 }

  condition:
    any of them
}