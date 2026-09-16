rule TTP_XOR_MULT_DOSStub_6409 {
  strings:
    $key_6409 = { 30 61 [2] 44 79 [2] 03 7b [2] 44 6a [2] 0a 66 [2] 06 6c [2] 11 67 [2] 0a 29 [2] 37 }

  condition:
    any of them
}