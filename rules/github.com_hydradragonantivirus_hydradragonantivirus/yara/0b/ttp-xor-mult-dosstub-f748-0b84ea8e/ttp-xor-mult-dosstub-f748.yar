rule TTP_XOR_MULT_DOSStub_f748 {
  strings:
    $key_f748 = { a3 20 [2] d7 38 [2] 90 3a [2] d7 2b [2] 99 27 [2] 95 2d [2] 82 26 [2] 99 68 [2] a4 }

  condition:
    any of them
}