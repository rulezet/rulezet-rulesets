rule TTP_XOR_MULT_DOSStub_44e5 {
  strings:
    $key_44e5 = { 10 8d [2] 64 95 [2] 23 97 [2] 64 86 [2] 2a 8a [2] 26 80 [2] 31 8b [2] 2a c5 [2] 17 }

  condition:
    any of them
}