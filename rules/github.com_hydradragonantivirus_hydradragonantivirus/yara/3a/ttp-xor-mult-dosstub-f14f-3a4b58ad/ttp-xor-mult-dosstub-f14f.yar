rule TTP_XOR_MULT_DOSStub_f14f {
  strings:
    $key_f14f = { a5 27 [2] d1 3f [2] 96 3d [2] d1 2c [2] 9f 20 [2] 93 2a [2] 84 21 [2] 9f 6f [2] a2 }

  condition:
    any of them
}