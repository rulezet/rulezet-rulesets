rule TTP_XOR_MULT_DOSStub_f26f {
  strings:
    $key_f26f = { a6 07 [2] d2 1f [2] 95 1d [2] d2 0c [2] 9c 00 [2] 90 0a [2] 87 01 [2] 9c 4f [2] a1 }

  condition:
    any of them
}