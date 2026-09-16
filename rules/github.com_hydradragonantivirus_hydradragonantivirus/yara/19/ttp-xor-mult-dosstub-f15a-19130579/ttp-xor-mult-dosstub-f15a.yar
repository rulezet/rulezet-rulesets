rule TTP_XOR_MULT_DOSStub_f15a {
  strings:
    $key_f15a = { a5 32 [2] d1 2a [2] 96 28 [2] d1 39 [2] 9f 35 [2] 93 3f [2] 84 34 [2] 9f 7a [2] a2 }

  condition:
    any of them
}