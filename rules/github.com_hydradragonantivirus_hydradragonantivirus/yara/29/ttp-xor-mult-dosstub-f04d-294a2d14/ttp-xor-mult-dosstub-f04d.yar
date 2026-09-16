rule TTP_XOR_MULT_DOSStub_f04d {
  strings:
    $key_f04d = { a4 25 [2] d0 3d [2] 97 3f [2] d0 2e [2] 9e 22 [2] 92 28 [2] 85 23 [2] 9e 6d [2] a3 }

  condition:
    any of them
}