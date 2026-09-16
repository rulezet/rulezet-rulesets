rule TTP_XOR_MULT_DOSStub_07e5 {
  strings:
    $key_07e5 = { 53 8d [2] 27 95 [2] 60 97 [2] 27 86 [2] 69 8a [2] 65 80 [2] 72 8b [2] 69 c5 [2] 54 }

  condition:
    any of them
}