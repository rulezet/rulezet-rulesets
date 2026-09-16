rule TTP_XOR_MULT_DOSStub_641b {
  strings:
    $key_641b = { 30 73 [2] 44 6b [2] 03 69 [2] 44 78 [2] 0a 74 [2] 06 7e [2] 11 75 [2] 0a 3b [2] 37 }

  condition:
    any of them
}