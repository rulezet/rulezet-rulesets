rule TTP_XOR_MULT_DOSStub_f25d {
  strings:
    $key_f25d = { a6 35 [2] d2 2d [2] 95 2f [2] d2 3e [2] 9c 32 [2] 90 38 [2] 87 33 [2] 9c 7d [2] a1 }

  condition:
    any of them
}