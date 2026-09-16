rule TTP_XOR_MULT_DOSStub_52e5 {
  strings:
    $key_52e5 = { 06 8d [2] 72 95 [2] 35 97 [2] 72 86 [2] 3c 8a [2] 30 80 [2] 27 8b [2] 3c c5 [2] 01 }

  condition:
    any of them
}