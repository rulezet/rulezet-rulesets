rule TTP_XOR_MULT_DOSStub_f47f {
  strings:
    $key_f47f = { a0 17 [2] d4 0f [2] 93 0d [2] d4 1c [2] 9a 10 [2] 96 1a [2] 81 11 [2] 9a 5f [2] a7 }

  condition:
    any of them
}