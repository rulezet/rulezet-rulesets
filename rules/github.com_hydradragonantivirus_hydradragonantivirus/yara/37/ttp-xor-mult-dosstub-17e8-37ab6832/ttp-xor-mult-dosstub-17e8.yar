rule TTP_XOR_MULT_DOSStub_17e8 {
  strings:
    $key_17e8 = { 43 80 [2] 37 98 [2] 70 9a [2] 37 8b [2] 79 87 [2] 75 8d [2] 62 86 [2] 79 c8 [2] 44 }

  condition:
    any of them
}