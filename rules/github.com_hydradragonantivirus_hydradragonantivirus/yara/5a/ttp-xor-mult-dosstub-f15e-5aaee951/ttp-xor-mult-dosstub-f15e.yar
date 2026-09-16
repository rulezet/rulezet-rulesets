rule TTP_XOR_MULT_DOSStub_f15e {
  strings:
    $key_f15e = { a5 36 [2] d1 2e [2] 96 2c [2] d1 3d [2] 9f 31 [2] 93 3b [2] 84 30 [2] 9f 7e [2] a2 }

  condition:
    any of them
}