rule TTP_XOR_MULT_DOSStub_3048 {
  strings:
    $key_3048 = { 64 20 [2] 10 38 [2] 57 3a [2] 10 2b [2] 5e 27 [2] 52 2d [2] 45 26 [2] 5e 68 [2] 63 }

  condition:
    any of them
}