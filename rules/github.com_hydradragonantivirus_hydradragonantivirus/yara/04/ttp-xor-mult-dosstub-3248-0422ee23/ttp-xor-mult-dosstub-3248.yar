rule TTP_XOR_MULT_DOSStub_3248 {
  strings:
    $key_3248 = { 66 20 [2] 12 38 [2] 55 3a [2] 12 2b [2] 5c 27 [2] 50 2d [2] 47 26 [2] 5c 68 [2] 61 }

  condition:
    any of them
}