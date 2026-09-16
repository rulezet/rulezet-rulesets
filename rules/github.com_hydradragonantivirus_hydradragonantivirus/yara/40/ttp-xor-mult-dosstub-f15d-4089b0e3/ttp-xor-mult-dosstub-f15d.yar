rule TTP_XOR_MULT_DOSStub_f15d {
  strings:
    $key_f15d = { a5 35 [2] d1 2d [2] 96 2f [2] d1 3e [2] 9f 32 [2] 93 38 [2] 84 33 [2] 9f 7d [2] a2 }

  condition:
    any of them
}