rule TTP_XOR_MULT_DOSStub_32e5 {
  strings:
    $key_32e5 = { 66 8d [2] 12 95 [2] 55 97 [2] 12 86 [2] 5c 8a [2] 50 80 [2] 47 8b [2] 5c c5 [2] 61 }

  condition:
    any of them
}