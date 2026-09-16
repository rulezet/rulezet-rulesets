rule TTP_XOR_MULT_DOSStub_f54f {
  strings:
    $key_f54f = { a1 27 [2] d5 3f [2] 92 3d [2] d5 2c [2] 9b 20 [2] 97 2a [2] 80 21 [2] 9b 6f [2] a6 }

  condition:
    any of them
}