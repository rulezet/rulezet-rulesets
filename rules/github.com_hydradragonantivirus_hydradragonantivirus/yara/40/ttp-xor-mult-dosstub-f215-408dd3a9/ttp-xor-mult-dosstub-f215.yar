rule TTP_XOR_MULT_DOSStub_f215 {
  strings:
    $key_f215 = { a6 7d [2] d2 65 [2] 95 67 [2] d2 76 [2] 9c 7a [2] 90 70 [2] 87 7b [2] 9c 35 [2] a1 }

  condition:
    any of them
}