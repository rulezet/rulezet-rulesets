rule TTP_XOR_MULT_DOSStub_f71f {
  strings:
    $key_f71f = { a3 77 [2] d7 6f [2] 90 6d [2] d7 7c [2] 99 70 [2] 95 7a [2] 82 71 [2] 99 3f [2] a4 }

  condition:
    any of them
}