rule TTP_XOR_MULT_DOSStub_4758 {
  strings:
    $key_4758 = { 13 30 [2] 67 28 [2] 20 2a [2] 67 3b [2] 29 37 [2] 25 3d [2] 32 36 [2] 29 78 [2] 14 }

  condition:
    any of them
}