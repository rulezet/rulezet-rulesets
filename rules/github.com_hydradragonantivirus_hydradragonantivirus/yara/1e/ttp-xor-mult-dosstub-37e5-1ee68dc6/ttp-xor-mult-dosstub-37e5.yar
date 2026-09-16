rule TTP_XOR_MULT_DOSStub_37e5 {
  strings:
    $key_37e5 = { 63 8d [2] 17 95 [2] 50 97 [2] 17 86 [2] 59 8a [2] 55 80 [2] 42 8b [2] 59 c5 [2] 64 }

  condition:
    any of them
}