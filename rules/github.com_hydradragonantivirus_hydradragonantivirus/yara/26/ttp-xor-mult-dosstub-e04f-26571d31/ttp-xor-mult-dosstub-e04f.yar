rule TTP_XOR_MULT_DOSStub_e04f {
  strings:
    $key_e04f = { b4 27 [2] c0 3f [2] 87 3d [2] c0 2c [2] 8e 20 [2] 82 2a [2] 95 21 [2] 8e 6f [2] b3 }

  condition:
    any of them
}