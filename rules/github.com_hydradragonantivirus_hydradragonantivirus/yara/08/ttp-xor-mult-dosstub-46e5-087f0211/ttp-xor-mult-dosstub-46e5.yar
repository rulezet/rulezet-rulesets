rule TTP_XOR_MULT_DOSStub_46e5 {
  strings:
    $key_46e5 = { 12 8d [2] 66 95 [2] 21 97 [2] 66 86 [2] 28 8a [2] 24 80 [2] 33 8b [2] 28 c5 [2] 15 }

  condition:
    any of them
}