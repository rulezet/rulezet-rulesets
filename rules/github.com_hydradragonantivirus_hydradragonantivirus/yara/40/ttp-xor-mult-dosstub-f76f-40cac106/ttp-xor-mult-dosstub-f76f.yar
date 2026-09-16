rule TTP_XOR_MULT_DOSStub_f76f {
  strings:
    $key_f76f = { a3 07 [2] d7 1f [2] 90 1d [2] d7 0c [2] 99 00 [2] 95 0a [2] 82 01 [2] 99 4f [2] a4 }

  condition:
    any of them
}