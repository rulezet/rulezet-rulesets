rule TTP_XOR_MULT_DOSStub_17e5 {
  strings:
    $key_17e5 = { 43 8d [2] 37 95 [2] 70 97 [2] 37 86 [2] 79 8a [2] 75 80 [2] 62 8b [2] 79 c5 [2] 44 }

  condition:
    any of them
}