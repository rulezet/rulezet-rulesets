rule TTP_XOR_MULT_DOSStub_f255 {
  strings:
    $key_f255 = { a6 3d [2] d2 25 [2] 95 27 [2] d2 36 [2] 9c 3a [2] 90 30 [2] 87 3b [2] 9c 75 [2] a1 }

  condition:
    any of them
}