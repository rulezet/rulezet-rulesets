rule TTP_XOR_MULT_DOSStub_f17f {
  strings:
    $key_f17f = { a5 17 [2] d1 0f [2] 96 0d [2] d1 1c [2] 9f 10 [2] 93 1a [2] 84 11 [2] 9f 5f [2] a2 }

  condition:
    any of them
}