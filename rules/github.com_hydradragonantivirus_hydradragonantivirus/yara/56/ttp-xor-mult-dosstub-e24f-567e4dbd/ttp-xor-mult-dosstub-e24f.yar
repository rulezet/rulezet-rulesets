rule TTP_XOR_MULT_DOSStub_e24f {
  strings:
    $key_e24f = { b6 27 [2] c2 3f [2] 85 3d [2] c2 2c [2] 8c 20 [2] 80 2a [2] 97 21 [2] 8c 6f [2] b1 }

  condition:
    any of them
}