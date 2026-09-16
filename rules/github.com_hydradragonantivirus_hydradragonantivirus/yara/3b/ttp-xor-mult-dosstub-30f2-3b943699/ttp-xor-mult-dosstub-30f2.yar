rule TTP_XOR_MULT_DOSStub_30f2 {
  strings:
    $key_30f2 = { 64 9a [2] 10 82 [2] 57 80 [2] 10 91 [2] 5e 9d [2] 52 97 [2] 45 9c [2] 5e d2 [2] 63 }

  condition:
    any of them
}