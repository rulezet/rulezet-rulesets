rule TTP_XOR_MULT_DOSStub_e14f {
  strings:
    $key_e14f = { b5 27 [2] c1 3f [2] 86 3d [2] c1 2c [2] 8f 20 [2] 83 2a [2] 94 21 [2] 8f 6f [2] b2 }

  condition:
    any of them
}