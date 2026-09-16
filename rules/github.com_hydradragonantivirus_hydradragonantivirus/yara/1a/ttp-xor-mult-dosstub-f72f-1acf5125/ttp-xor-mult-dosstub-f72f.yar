rule TTP_XOR_MULT_DOSStub_f72f {
  strings:
    $key_f72f = { a3 47 [2] d7 5f [2] 90 5d [2] d7 4c [2] 99 40 [2] 95 4a [2] 82 41 [2] 99 0f [2] a4 }

  condition:
    any of them
}