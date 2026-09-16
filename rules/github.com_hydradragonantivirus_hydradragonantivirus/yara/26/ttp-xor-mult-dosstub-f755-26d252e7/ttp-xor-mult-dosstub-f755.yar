rule TTP_XOR_MULT_DOSStub_f755 {
  strings:
    $key_f755 = { a3 3d [2] d7 25 [2] 90 27 [2] d7 36 [2] 99 3a [2] 95 30 [2] 82 3b [2] 99 75 [2] a4 }

  condition:
    any of them
}