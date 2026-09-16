rule TTP_XOR_MULT_DOSStub_e64f {
  strings:
    $key_e64f = { b2 27 [2] c6 3f [2] 81 3d [2] c6 2c [2] 88 20 [2] 84 2a [2] 93 21 [2] 88 6f [2] b5 }

  condition:
    any of them
}