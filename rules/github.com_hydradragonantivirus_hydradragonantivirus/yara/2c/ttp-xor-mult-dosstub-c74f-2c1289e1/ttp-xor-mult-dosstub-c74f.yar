rule TTP_XOR_MULT_DOSStub_c74f {
  strings:
    $key_c74f = { 93 27 [2] e7 3f [2] a0 3d [2] e7 2c [2] a9 20 [2] a5 2a [2] b2 21 [2] a9 6f [2] 94 }

  condition:
    any of them
}