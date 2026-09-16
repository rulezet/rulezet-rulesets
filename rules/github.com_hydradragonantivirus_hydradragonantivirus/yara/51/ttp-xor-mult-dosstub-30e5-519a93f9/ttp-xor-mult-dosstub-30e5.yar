rule TTP_XOR_MULT_DOSStub_30e5 {
  strings:
    $key_30e5 = { 64 8d [2] 10 95 [2] 57 97 [2] 10 86 [2] 5e 8a [2] 52 80 [2] 45 8b [2] 5e c5 [2] 63 }

  condition:
    any of them
}