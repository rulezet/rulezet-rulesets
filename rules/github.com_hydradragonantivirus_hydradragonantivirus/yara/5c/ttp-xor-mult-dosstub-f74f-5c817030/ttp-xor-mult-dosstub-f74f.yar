rule TTP_XOR_MULT_DOSStub_f74f {
  strings:
    $key_f74f = { a3 27 [2] d7 3f [2] 90 3d [2] d7 2c [2] 99 20 [2] 95 2a [2] 82 21 [2] 99 6f [2] a4 }

  condition:
    any of them
}