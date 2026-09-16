rule TTP_XOR_MULT_DOSStub_44e8 {
  strings:
    $key_44e8 = { 10 80 [2] 64 98 [2] 23 9a [2] 64 8b [2] 2a 87 [2] 26 8d [2] 31 86 [2] 2a c8 [2] 17 }

  condition:
    any of them
}