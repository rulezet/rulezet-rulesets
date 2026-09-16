rule TTP_XOR_MULT_DOSStub_f258 {
  strings:
    $key_f258 = { a6 30 [2] d2 28 [2] 95 2a [2] d2 3b [2] 9c 37 [2] 90 3d [2] 87 36 [2] 9c 78 [2] a1 }

  condition:
    any of them
}