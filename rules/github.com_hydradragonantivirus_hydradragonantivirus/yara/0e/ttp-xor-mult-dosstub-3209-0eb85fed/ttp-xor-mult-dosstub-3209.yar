rule TTP_XOR_MULT_DOSStub_3209 {
  strings:
    $key_3209 = { 66 61 [2] 12 79 [2] 55 7b [2] 12 6a [2] 5c 66 [2] 50 6c [2] 47 67 [2] 5c 29 [2] 61 }

  condition:
    any of them
}